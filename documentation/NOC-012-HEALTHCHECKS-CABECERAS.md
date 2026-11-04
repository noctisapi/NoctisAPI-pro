# NOC-012 — Auditar y separar healthchecks y cabeceras internas

Issue: [#15 NOC-012 — Auditar y separar healthchecks y cabeceras internas](https://github.com/noctisapi/NoctisAPI-pro/issues/15)
Depende de: NOC-005, NOC-010 (ambas fusionadas) — esta rama parte de `main` directamente.

## Objetivo

Eliminar vías para evitar telemetría, controles de seguridad o exponer estado real.

## 1. El gate real (`_is_monitor`) ya es seguro — verificado, no asumido

`app/honeypot_public.py::_is_monitor()` (`:635-641`) no comprueba la mera presencia de
`X-Internal-Monitor` — compara su valor contra `HP_MONITOR_SECRET` (variable de entorno) con
`secrets.compare_digest` (tiempo constante), y **falla cerrado** si el secreto no está
configurado (`if not _HP_MONITOR_SECRET: return False`). Un atacante no puede satisfacerlo sin
conocer ese secreto. Esto ya cumplía el criterio "no hay bypass de registro por cabeceras
externas" antes de esta Issue — el problema no estaba ahí, sino en quién más toca esa misma
cabecera.

## 2. Hallazgo 1 (corregido): `app/honeypot_monitor.py` enviaba un literal, no el secreto real

`HoneypotAvailabilityMonitor._base_headers()` (`:429-433`) fijaba
`"X-Internal-Monitor": "1"` **a secas**, sin leer `HP_MONITOR_SECRET` — a diferencia de
`app/panel_mvp.py:2444-2445`, que sí usa el secreto real para su propia llamada al catálogo
OpenAPI. Consecuencia práctica: si un operador configura `HP_MONITOR_SECRET` con un valor real
(lo esperable, dado el diseño de tiempo constante), el propio monitor interno de `admin` **deja
de ser reconocido como interno** — sus comprobaciones pasarían a tratarse como tráfico normal,
sin que esto sea una vía de ataque, pero sí un bug de funcionalidad que silenciosamente
contradice el propósito del monitor.

**Corregido**: `_base_headers()` ahora lee `HP_MONITOR_SECRET` (mismo patrón que
`panel_mvp.py`) y solo añade la cabecera si hay un secreto real configurado; nunca un literal.

## 3. Hallazgo 2 (corregido): el router público `/health` etiquetaba tráfico ajeno como "interno"

`hp-health` (el router de Traefik que atiende `/health` y `/status` en el dominio público,
entrypoint `websecure`, alcanzable por **cualquiera** en Internet) usaba el middleware
`hp-monitor-headers`, que inyecta `X-Internal-Monitor: 1` — el mismo middleware que el router
`hp-internal` (genuinamente interno, entrypoint `webinternal`, solo loopback). Es decir: Traefik
etiquetaba como "monitor interno" el tráfico de **cualquier visitante público** que pidiera
`/health` o `/status`.

Esto era inocuo hoy solo porque el valor inyectado ("1") nunca coincide con un
`HP_MONITOR_SECRET` real — pero es una confusión de diseño innecesaria y un riesgo latente: si
algún día alguien simplifica `_is_monitor()` o configura `HP_MONITOR_SECRET=1` (un valor débil y
adivinable) pensando que así "activa" el monitor, cualquier atacante podría autoidentificarse
como monitor interno sin más que pedir `/health` — exactamente el "bypass de registro por
cabeceras externas" que esta Issue existe para prevenir.

**Corregido**: `hp-health` pasa a usar su propio middleware de rate-limit
(`hp-health-ratelimit`, mismos valores 30/60 que antes) **sin** `hp-monitor-headers`.
`hp-internal` no cambia — sigue usando `hp-monitor-headers,hp-monitor-ratelimit`, correctamente,
porque esa ruta sí es genuinamente interna.

## 4. Verificación real

```bash
# hp-health (público, HTTPS) -- NO debe llevar X-Internal-Monitor
curl -sk https://traefik/health -H "Host: <dominio>" | grep -i x-internal-monitor
# (vacío)

# hp-internal (webinternal, interno) -- SÍ debe llevar X-Internal-Monitor
curl -s http://traefik:8081/ -H "Host: <dominio>"  | grep -i x-internal-monitor
# X-Internal-Monitor: 1
```

Confirmado con Traefik v3.7.16 real + `whoami`: el router público deja de inyectar la cabecera;
el router interno la sigue inyectando sin cambios.

## 5. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1019 passed, 1 skipped, 2 xfailed   (1017 + 2 tests nuevos de esta Issue)
```

Nuevo `tests/test_honeypot_monitor.py` (2 tests): sin `HP_MONITOR_SECRET` configurado, la
cabecera no se envía en absoluto (antes se enviaba el literal "1"); con secreto configurado, se
envía el secreto real, nunca "1".

Más la verificación real de la sección 4 (requiere Docker; documentada como evidencia manual).

## 6. Criterios de aceptación

- [x] La API sigue exponiendo únicamente respuestas de engaño cuando corresponde — sin cambios
      de comportamiento de la API señuelo; solo se corrige el etiquetado interno de Traefik.
- [x] Los checks operativos requieren ruta interna autenticada o local — el monitor de `admin`
      ya pasa por el entrypoint interno (`webinternal`, NOC-011) y ahora se autentica con el
      secreto real, no con un literal adivinable.
- [x] No hay bypass de registro por cabeceras externas — confirmado que `_is_monitor()` ya era
      seguro (sección 1); cerrados los dos puntos que lo debilitaban por el lado de quién envía
      la cabecera (secciones 2 y 3).

## 7. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: cierra un riesgo latente (etiquetado público como "interno") y corrige un bug
  de funcionalidad del propio monitor — ambos sin haber sido explotables hoy, dado el diseño
  fail-closed de `_is_monitor()`, pero sí reduciendo el margen de error futuro.
- **Compatibilidad**: `hp-health` sigue con el mismo rate limit (30/60); el monitor de `admin`
  solo deja de enviar un valor inútil — si `HP_MONITOR_SECRET` nunca se configura, el
  comportamiento observable es idéntico (la cabecera simplemente no se envía en ningún caso, en
  vez de enviarse con un valor que nunca hizo nada).
- **Despliegue**: ninguno — ambos cambios son de configuración/código sin impacto de infra.
- **Rollback**: trivial, revertir el commit restaura el literal "1" y el middleware compartido.
