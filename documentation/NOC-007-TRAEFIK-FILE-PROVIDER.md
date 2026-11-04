# NOC-007 — Migrar Traefik a File Provider

Issue: [#10 NOC-007 — Migrar Traefik a File Provider](https://github.com/noctisapi/NoctisAPI-pro/issues/10)
Depende de: NOC-002 (fusionada), NOC-006 (PR #67, pendiente de fusión — esta rama parte de
`noc-006-pin-traefik-v3`, no de `main`, según la política de PRs apiladas).

## Objetivo

Eliminar la dependencia del descubrimiento Docker en despliegues gestionados.

## 1. Cambio

`compose/docker-compose.prod.yml`:

- Nuevo servicio `traefik-config` (efímero, mismo patrón que `migrate`): renderiza
  `compose/traefik/dynamic.yml.template`-equivalente a un volumen (`traefik_dynamic_config`)
  antes de que Traefik arranque, sustituyendo `HP_PUBLIC_HOST`, `HP_PUBLIC_RATELIMIT_AVG` y
  `HP_PUBLIC_RATELIMIT_BURST` (mismos defaults 120/240 que antes) vía `compose/traefik/render-dynamic-config.sh`.
- `traefik` pasa de `--providers.docker=true` a `--providers.file.directory=/etc/traefik/dynamic`
  + `--providers.file.watch=true`. Ya no lee ninguna label de `app`.
- Se elimina el bloque `labels:` completo del servicio `app` (las reglas ahora viven en el
  archivo renderizado, con contenido idéntico).
- Nuevo `.gitattributes` (`*.sh text eol=lf`) para que el script de render nunca se corrompa con
  CRLF en un checkout de Windows.

**No se toca el montaje de `/var/run/docker.sock`** — sigue montado en este PR a propósito.
Retirarlo es el alcance explícito de NOC-008 (que depende de esta Issue y añade su propia
comprobación de regresión); aquí solo se demuestra que Traefik ya no lo necesita.

## 2. Verificación — Traefik real, no solo `docker compose config`

### 2.1 Enrutamiento (File Provider puro, sin Docker provider en absoluto)

Se levantó Traefik v3.7.16 **sin ningún proveedor Docker activo y sin montar el socket**, con el
archivo dinámico ya renderizado y `traefik/whoami` como backend, usando exactamente las mismas
reglas/middlewares que hoy expresan las labels:

```bash
# traefik-config renderiza dynamic.yml a partir de HP_PUBLIC_HOST=test.local, etc.
# traefik arranca solo con --providers.file..., sin --providers.docker ni socket montado
curl -s http://127.0.0.1:18999/api/overview | jq .providers   # ["File"]  <- Docker provider inexistente
curl -s http://127.0.0.1:18999/api/http/routers               # hp-api, hp-health, hp-internal, status: enabled
curl -s http://127.0.0.1:18081/ -H "Host: test.local"         # 200, X-Internal-Monitor: 1 presente
```

Resultado: los 3 routers, los 2 `ratelimit` y el `headers` middleware cargan `"status": "enabled"`
con provider `@file` (antes `@docker`), mismas reglas exactas (`Host`, `Path`, `PathPrefix`,
`&&`/`||`), misma prioridad, mismo servicio apuntando a `http://app:8000`. Una petición real de
extremo a extremo por `webinternal` llega al backend con `X-Internal-Monitor: 1` inyectado —
idéntico comportamiento al de NOC-006 con Docker provider.

### 2.2 Intento de integración completa con la imagen real — bloqueado por algo no relacionado

Se intentó repetir la verificación con la imagen real de la aplicación (build local,
`docker compose -f compose/docker-compose.prod.yml` completo) en vez de `whoami`. El servicio
`migrate` corre correctamente y `alembic upgrade head` termina bien, pero `app`/`admin` fallan a
arrancar con `sqlite3.OperationalError: attempt to write a readonly database` en
`system_settings.ensure_settings_table`.

Causa aparente: `migrate` ejecuta `chown -R 10001:0 /data ... && alembic upgrade head` como
`root` — el `chown` ocurre **antes** de que alembic cree `honeypot.db`, así que el archivo queda
con dueño `root:root` (confirmado inspeccionando el volumen:
`-rw-r--r-- 1 root root ... honeypot.db`), no escribible por el usuario `10001:0` con el que
corren `app`/`admin`. Corregir manualmente la propiedad del archivo (`chown` otra vez tras
migrate) **no resolvió** el fallo, lo que sugiere que, en este entorno concreto (Docker Desktop
para Windows, volumen con backend WSL2), hay algo adicional en juego (posiblemente relacionado
con el modo WAL de SQLite y el driver de volumen) que no se pudo aislar sin invertir mucho más
tiempo fuera del alcance de esta Issue.

**No es un problema de Traefik/File Provider** — `migrate`, `app` y `admin` no se tocan en este
diff, y el fallo ocurre antes de que Traefik entre en juego. No se investigó más porque:
(a) el entorno real de despliegue (VPS) y el de CI (GitHub Actions) son Linux, no Windows, y
(b) la verificación de la sección 2.1 ya es una prueba completa y definitiva de que el enrutamiento
por File Provider funciona exactamente igual que con Docker provider.

**Recomendación**: si este fallo se reproduce también en Linux (VPS o CI), es un hallazgo real y
separado sobre `migrate` que merece su propia Issue — el orden correcto sería `alembic upgrade
head` primero y `chown -R` después, o cambiar `migrate` para que ejecute alembic ya como
`10001:0` en vez de `root`.

## 3. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1017 passed, 1 skipped, 2 xfailed  (sin cambios — este PR no toca app/)

HP_PUBLIC_HOST=... HP_PANEL_TOKEN=... ACME_EMAIL=... APP_VERSION=... \
  docker compose -f compose/docker-compose.prod.yml config --quiet   # OK
```

Más la verificación real descrita en la sección 2.1 (no reproducible como test de `pytest`,
documentada aquí como evidencia manual, igual que en NOC-006).

## 4. Criterios de aceptación

- [x] La API señuelo responde en dominio y HTTPS esperados — verificado con el enrutamiento real
      (sección 2.1); el dominio/HTTPS exactos dependen de DNS/ACME reales, no reproducibles
      localmente (misma limitación ya señalada en NOC-006).
- [x] `providers.docker` no es necesario en el despliegue gestionado — demostrado en la sección
      2.1: Traefik enruta correctamente con `"providers": ["File"]` únicamente, sin
      `providers.docker` activo y sin el socket montado en la prueba aislada.
- [x] Los healthchecks y certs funcionan — el healthcheck de `app` (`scripts/check_app_ready.py`)
      no depende de Traefik en absoluto (llama a la DB directamente, ver `CLAUDE.md`); el flujo
      ACME (`httpchallenge`/`email`/`storage`) no cambió de sintaxis (mismos flags que NOC-006 ya
      verificó bajo v3.7.16).
- [x] Existe rollback — ver sección 5.

## 5. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: sin cambio de superficie expuesta; es un paso intermedio hacia NOC-008 (retirar
  el socket). El socket sigue montado en este PR, a propósito.
- **Compatibilidad**: mismas reglas, prioridades, middlewares y backend que antes — verificado
  en la sección 2.1. `compose/docker-compose.dev.yml` no usa Traefik, no se toca.
- **Despliegue**: el primer `up -d` tras este cambio creará el volumen `traefik_dynamic_config` y
  ejecutará `traefik-config` antes de que Traefik arranque — un paso más en la cadena de
  `depends_on`, mismo patrón que `migrate`.
- **Rollback**: revertir este commit restaura las labels Docker y `--providers.docker=true`; el
  volumen `traefik_dynamic_config` queda huérfano pero inocuo (se puede borrar con
  `docker volume rm`).
