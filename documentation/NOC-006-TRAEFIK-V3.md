# NOC-006 — Actualizar y fijar la versión de Traefik

Issue: [#9 NOC-006 — Actualizar y fijar la versión de Traefik](https://github.com/noctisapi/NoctisAPI-pro/issues/9)
Depende de: NOC-003 (CI/staging, PR #64, fusionada), NOC-004 (ADRs/mapa de migración, PR #65, fusionada).

## Objetivo

Evitar mantener una rama obsoleta de Traefik y asegurar reproducibilidad.

## 1. Estado de versión (verificado hoy, no de memoria)

`compose/docker-compose.prod.yml` fijaba `traefik:v2.11`. Traefik v2 ya no recibe soporte de
seguridad activo; la rama soportada actualmente es v3, con **v3.7.16** como último parche
estable. Fuentes consultadas: [endoflife.date/traefik](https://endoflife.date/traefik),
[versio.io](https://www.versio.io/es/product-release-end-of-life-eol-traefik-labs-traefik-proxy.html).

## 2. Compatibilidad de sintaxis — verificada ejecutando Traefik v3.7, no solo leyendo la guía de migración

La guía oficial de migración v2→v3
([doc.traefik.io/traefik/v3.3/migration/v2-to-v3](https://doc.traefik.io/traefik/v3.3/migration/v2-to-v3/))
señala cambios de sintaxis en los matchers de rutas (`Headers`→`Header`, `HostHeader` eliminado,
`PathPrefix` ya no admite regex, los matchers ya no aceptan múltiples valores separados por
coma) y en el proveedor Docker (`providers.docker.swarmMode` y `providers.docker.tls.caOptional`
eliminados — fatales al arrancar si están presentes). La guía no cubre explícitamente
`ratelimit`, `headers.customrequestheaders`, `certificatesresolvers`/ACME, ni la sintaxis de
`entrypoints` — exactamente lo que usa nuestra configuración.

Por eso no basta con leer la documentación: se levantó un Traefik v3.7.16 real
(`traefik/whoami` como backend) con **las mismas labels Docker que usa hoy el servicio `app`**
en `compose/docker-compose.prod.yml` (rutas `hp-api`/`hp-health`/`hp-internal`, middlewares
`ratelimit` y `headers.customrequestheaders`, entrypoints `web`/`websecure`/`webinternal`,
`certificatesresolvers.letsencrypt.acme.*`), sin ningún cambio de sintaxis respecto al archivo
actual:

```bash
docker compose -f /tmp/traefik_v3_test/docker-compose.yml up -d
curl -s http://127.0.0.1:18999/api/http/routers   # API de Traefik, solo para esta prueba
curl -s http://127.0.0.1:18999/api/http/middlewares
curl -s http://127.0.0.1:18081/ -H "Host: test.local"   # petición real de extremo a extremo
```

Resultado:
- Los 3 routers (`hp-api`, `hp-health`, `hp-internal`) aparecen `"status": "enabled"` con la
  regla exacta de hoy (`Host(...)`, `Path(...) || Path(...)`, `PathPrefix(...)`) — **nuestra
  sintaxis de reglas ya es nativamente v3**, no hace falta `ruleSyntax=v2` ni
  `core.defaultRuleSyntax=v2` (el modo de compatibilidad que Traefik ofrece para quien sí tenga
  reglas v2-only, y que ellos mismos marcan como deprecado).
- Ambos middlewares `ratelimit` (`average`/`burst`) y el `headers` con
  `customrequestheaders.X-Internal-Monitor=1` cargan `"status": "enabled"` sin cambios.
- Petición real a través de `webinternal` → enrutada por `hp-internal` → el backend recibe la
  cabecera `X-Internal-Monitor: 1` inyectada — la cadena completa (discovery por labels Docker +
  matching de reglas + prioridades + middlewares) funciona igual que con v2.11.
- Sin warnings de deprecación en los logs (`grep -iE "deprecat|v2|legacy"` → vacío). Los únicos
  `ERR` en el log son de ACME ("HTTP challenge is not enabled" / no existe `/letsencrypt/acme.json`)
  — esperado en esta prueba local sin dominio público ni volumen de certificados, no relacionado
  con sintaxis.

No se pudo verificar en esta prueba local el ciclo completo de emisión de certificado ACME real
(exige un dominio público resoluble y el puerto 80 accesible desde Internet) — eso solo se puede
confirmar en el primer despliegue real con esta versión, igual que ya ocurriría con cualquier
cambio de versión de Traefik.

## 3. Cambio aplicado

Un único cambio de línea en `compose/docker-compose.prod.yml`:

```diff
   traefik:
-    image: traefik:v2.11
+    image: traefik:v3.7.16
```

Ningún otro valor de TLS, rutas, middlewares o entrypoints fue modificado — confirmado por
`git diff` (un solo `-`/`+`) y por la prueba de la sección 2, que usó exactamente las mismas
labels ya presentes en el archivo.

## 4. Rollback

Revertir es un cambio de una línea en sentido inverso:

```bash
git revert <este-commit>
# o manualmente:
sed -i 's/traefik:v3.7.16/traefik:v2.11/' compose/docker-compose.prod.yml
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod pull
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod up -d
```

Sin migración de datos ni de certificados ACME de por medio — el volumen `traefik_letsencrypt`
no cambia de formato entre v2.11 y v3.7, y un `docker compose up -d` tras el pull reemplaza solo
el contenedor de Traefik.

## 5. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1017 passed, 1 skipped, 2 xfailed  (idéntico al baseline — este cambio no toca app/)

HP_PUBLIC_HOST=... HP_PANEL_TOKEN=... ACME_EMAIL=... APP_VERSION=... \
  docker compose -f compose/docker-compose.prod.yml config --quiet   # OK
```

Más la verificación real de Traefik v3.7 descrita en la sección 2 (no reproducible como test de
`pytest` porque requiere Docker-in-Docker; documentada aquí como evidencia manual).

## 6. Criterios de aceptación

- [x] Versión soportada y fijada — `traefik:v3.7.16`, pin exacto de parche (no solo de minor).
- [x] Configuración validada con esa versión — sección 2, prueba real de extremo a extremo, no
      solo lectura de la guía de migración.
- [x] No hay cambios no documentados en TLS ni rutas — sección 3, diff de una sola línea.

## 7. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: mejora — v2.11 ya no recibe parches de seguridad; v3.7.16 es la línea
  activamente soportada.
- **Compatibilidad**: sin cambios de comportamiento esperados — sección 2 verifica que las
  reglas/middlewares/entrypoints actuales funcionan igual bajo v3.7.16.
- **Despliegue**: el próximo `docker compose ... pull && up -d` en producción descargará la
  nueva imagen de Traefik; no requiere cambios en `.env.prod` ni en el volumen de certificados.
- **Rollback**: ver sección 4 — trivial, una línea, sin migración de datos.
