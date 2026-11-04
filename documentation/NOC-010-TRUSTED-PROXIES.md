# NOC-010 — Endurecer trusted proxies y cabeceras de origen

Issue: [#13 NOC-010 — Endurecer trusted proxies y cabeceras de origen](https://github.com/noctisapi/NoctisAPI-pro/issues/13)
Depende de: NOC-001, NOC-002 (ambas fusionadas) — esta rama parte de `main` directamente.

## Objetivo

Proteger identidad de IP y esquema frente a falsificación por cabeceras.

## 1. Alcance de la auditoría

`app/trusted_proxy.py` (IP real del cliente: `CF-Connecting-IP` → `X-Forwarded-For` → `X-Real-IP`
→ socket) y `app/reverse_proxy.py` (esquema/host/puerto públicos: `X-Forwarded-Proto/Host/Port`),
ambos ya auditados en `documentation/NOC-001-AUDITORIA-ARQUITECTURA.md`. Esta Issue profundiza:
revisa el código línea a línea, la cobertura de tests existente, y — lo que ningún test unitario
puede probar por sí solo — el comportamiento **real** de Traefik como el único proxy de la
topología actualmente soportada.

## 2. Hallazgo: la cobertura de tests ya existente cubre los 3 criterios de aceptación

`tests/test_trusted_proxy.py` (46 tests) y `tests/test_reverse_proxy.py` (42 tests) ya incluyen,
entre otros:

- **Suplantación bloqueada desde origen no confiable**: `test_untrusted_xff_ignored`,
  `test_untrusted_cf_connecting_ip_ignored`, `test_untrusted_x_real_ip_ignored`,
  `test_untrusted_all_headers_ignored`, `test_untrusted_emits_warning` (trusted_proxy);
  `test_untrusted_peer_ignores_forwarded_headers`, `test_untrusted_peer_does_not_rewrite`
  (reverse_proxy).
- **Proxy adicional, positivo y negativo**: `test_client_then_two_proxies`,
  `test_trusted_proxy_xff_multi_hop`, `test_forged_prefix_rightmost_non_trusted_returned`
  (atacante antepone una IP falsa — se ignora, se devuelve la real), `test_all_trusted_returns_leftmost`
  (cadena totalmente interna).
- **Prioridad de cabeceras correcta**: `test_cf_connecting_ip_takes_priority_over_xff`,
  `test_xff_takes_priority_over_x_real_ip`, etc.

No se encontró ninguna laguna de cobertura a nivel de unidad — por eso esta Issue no añade
código ni tests nuevos de "proxy adicional": ya existen y pasan.

```bash
pip install -r requirements-dev.txt
python -m pytest tests/test_trusted_proxy.py tests/test_reverse_proxy.py -v
# 88 passed (46 + 42)
```

## 3. Verificación real — lo que un test unitario no puede probar por sí solo

Los tests unitarios asumen que, cuando el peer directo es confiable, las cabeceras
`X-Forwarded-*` que trae la petición ya fueron fijadas honestamente por ese proxy — no se
verifica en ningún test que **Traefik realmente se comporte así**. Se comprobó levantando un
Traefik v3.7.16 real con `whoami` como backend, enviando una petición con cabeceras
`X-Forwarded-Host`/`-Proto`/`-Port`/`-For` ya forjadas por el "cliente" antes de llegar a Traefik:

```bash
curl http://traefik/ -H "Host: attacker-test.local" \
  -H "X-Forwarded-Host: evil.com" -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Port: 9999" -H "X-Forwarded-For: 203.0.113.99"
```

Resultado: whoami (que devuelve las cabeceras que recibió) muestra exactamente los mismos
valores con o sin las cabeceras forjadas — `X-Forwarded-Host: attacker-test.local`,
`X-Forwarded-Proto: http`, `X-Forwarded-Port: 80`, `X-Forwarded-For: <IP real del cliente>`.
**Traefik sobrescribe por completo estas cabeceras con los valores reales de la conexión que él
mismo observa; nunca pasa el valor del cliente.** Confirma que la suposición de confianza de
`app/reverse_proxy.py` (honrar las cabeceras del peer directo si es confiable) es segura en la
topología actual, porque el peer directo (Traefik) nunca refleja lo que el cliente externo le
envió.

También se comprobó qué pasa si una petición llega con un `X-Forwarded-For` **ya presente**
(simulando un futuro hop adicional delante de Traefik, p. ej. un CDN):

```bash
curl http://traefik/ -H "X-Forwarded-For: 203.0.113.50"
```

Resultado: Traefik **sustituye** por completo ese valor por la IP que él mismo ve (no lo
encadena/añade). Esto es correcto y seguro con la configuración estática actual (sin
`entryPoints.*.forwardedHeaders.trustedIPs`) — Traefik nunca confía en cabeceras previas de
nadie, así que no hay manera de inyectar una IP falsa a través de él. Pero es una nota a tener en
cuenta para el futuro: **si algún día se antepone un CDN/WAF (p. ej. Cloudflare) delante del
propio Traefik público** — no planeado hoy; NOC-016 solo pone Cloudflare Tunnel delante de la
**consola**, no de la API pública — habría que configurar `forwardedHeaders.trustedIPs` con los
rangos de ese CDN en el entrypoint correspondiente, o Traefik seguiría sustituyendo el
`X-Forwarded-For` real del atacante por la IP del propio CDN, rompiendo la fidelidad de
`resolve_client_ip()` y por tanto el actor tracking. No es un problema hoy porque esa topología
no existe todavía; se deja anotado para cuando NOC-016 (o cualquier Issue futura que ponga un
proxy adicional delante de la API pública) lo necesite.

## 4. PROXY Protocol — no aplica hoy

El alcance de la Issue menciona revisar PROXY Protocol. Verificado: no hay ninguna referencia a
PROXY Protocol en `compose/`, `app/` ni la documentación — ni Traefik lo tiene configurado en
ningún entrypoint, ni uvicorn lo soporta en este proyecto. No es una topología soportada hoy; no
hay nada que endurecer porque no existe superficie.

```bash
grep -rn "proxyProtocol\|PROXY_PROTOCOL\|PROXY protocol" compose/ app/ documentation/
# (sin resultados)
```

## 5. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1020 passed, 1 skipped, 2 xfailed   (sin cambios — esta Issue no modifica app/ ni tests/)
```

Más la verificación real de Traefik descrita en la sección 3 (requiere Docker; documentada aquí
como evidencia manual, mismo patrón que NOC-006/007/009).

## 6. Criterios de aceptación

- [x] Conexiones no confiables no pueden suplantar IP/esquema/origen — verificado a nivel de
      unidad (sección 2, ya cubierto) y a nivel de infraestructura real (sección 3).
- [x] Se preserva telemetría y actor tracking correcto — `resolve_client_ip()` sin cambios,
      cobertura de tests existente intacta.
- [x] Pruebas positivas y negativas con proxy adicional pasan — sección 2, ya satisfecho por la
      suite existente (`test_client_then_two_proxies`, `test_forged_prefix_rightmost_non_trusted_returned`,
      `test_all_trusted_returns_leftmost`).

## 7. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: ningún cambio de código — esta Issue confirma mediante verificación real que el
  endurecimiento ya implementado es efectivo en la topología actual, y documenta una
  consideración futura (CDN delante de la API pública) para cuando aplique.
- **Compatibilidad/Despliegue/Rollback**: no aplica — no se modificó ningún archivo de `app/`,
  `compose/` ni `tests/`.
