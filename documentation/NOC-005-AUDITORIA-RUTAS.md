# NOC-005 — Auditoría de rutas reales y de engaño

Issue: [#8 NOC-005 — Auditar rutas reales y de engaño](https://github.com/0x-unkwn0wn/noctisapi-pro/issues/8)
Depende de: NOC-001 (completada, en `main`).

## Objetivo

Detectar endpoints administrativos reales mezclados con la superficie señuelo, verificando
controles de acceso **efectivos** — no solo si una ruta está oculta de `/openapi.json`.

## Metodología

Inventario de los tres puntos de entrada HTTP del sistema: `app/honeypot_public.py` (puerto
8000, público), `app/pro_router.py` (montado dentro del mismo proceso/puerto que el anterior) y
`app/panel_mvp.py` (puerto 9001, interno). Para cada ruta: clasificación
`public-decoy` / `admin` / `operational`, y lectura directa del código del handler (no solo del
decorador) para determinar el control de acceso real. Dos rutas ambiguas por nombre/tags se
inspeccionaron a fondo (secciones 2 y 3) porque "oculto de OpenAPI" no implica "protegido".

## 1. Matriz de rutas

### `app/honeypot_public.py` (puerto 8000, público) — ~75 rutas

| Grupo | Rutas (ejemplo) | Clasificación | Control de acceso real |
|---|---|---|---|
| Recon/raíz | `/`, `/openapi.json`, `/docs`, `/redoc`, `/swagger`, `/.env`, `/config.json`, `/.well-known/security.txt` | public-decoy | Ninguno (por diseño; son el cebo) |
| Auth lure | `/auth/*`, `/v1/auth/token`, `/sessions*`, `/apikeys` | public-decoy | Emiten tokens falsos propios (`_mint_token`), trackean actor/score |
| Account/keys | `/v1/account`, `/v1/keys` | public-decoy | `require_bearer` — valida contra tokens **emitidos por el propio señuelo**, no credenciales reales |
| Admin/Internal lure | `/admin`, `/admin/users`, `/admin/audit`, `/internal/feature-flags`, `/internal/reload`, `/internal/migrate`, `/internal/config` | public-decoy | Igual que arriba: `require_bearer`/`require_api_key` contra secretos **auto-emitidos como cebo** (`_get_or_create_secret`); verificado en código (sección "Internal", abajo) — correctamente señuelo |
| DevOps/CI lure | `/webhooks/*`, `/ci/*`, `/artifacts/{id}`, `/jobs/{id}` | public-decoy | Sin auth real; devuelven datos fabricados |
| Business API lure | `/api/v1/users*`, `/api/v1/orders*`, `/api/v1/accounts`, `/api/v1/transactions`, `/api/v1/payments`, `/api/v1/reports/{id}` | public-decoy | Capa modular (catálogo/ResponseFactory o legacy) — ver `CLAUDE.md` |
| Consola/root lure | `/console/*`, `/root/shell`, `/root/console` | public-decoy | Sin auth real; el propio nombre es el cebo |
| Files lure | `/files*`, `/import`, `/backup/*` | public-decoy | `require_backup_token` contra secretos auto-emitidos — señuelo correcto |
| Admin secretos (lure encadenado) | `/admin/secrets` | public-decoy | `require_admin_secret` contra un secreto de cebo **previamente emitido** (p. ej. vía `/backup/download`) — correctamente señuelo, es un escalón más de la cadena de engaño |
| Infra/cloud lure | `/infra/vault`, `/cloud/metadata` | public-decoy | Sin auth real; devuelven datos fabricados de alta tentación |
| Legacy admin (oculto) | `/v1/admin/login`, `/v1/admin/status`, `/v1/admin/rotate`, `/v1/export/users`, `/v1/export/audit` | public-decoy | `require_bearer` (igual que el resto); verificado — correctamente señuelo a pesar del nombre |
| **Health** | `/health`, `/ready`, `/version` | `/health` operational real (inocuo); `/ready`/`/version` eran operational real (ver hallazgo §2) → **corregidas a señuelo en este PR** | `/health`: ninguno, inocuo. `/ready`/`/version`: ninguno antes del fix — ahora son señuelo, no necesitan auth |
| Health (señuelo) | `/status` | public-decoy | Correcto: jitter + actor tracking, sin datos reales |
| **PRO analytics** | `/pro/analytics/endpoints`, `/interest`, `/fingerprinting`, `/overview` | admin real | `require_admin_secret` era **efectivo solo en apariencia** (ver hallazgo §3) → **corregido en este PR**: ahora `require_internal_admin_token` (HMAC contra `HP_PANEL_TOKEN` real) |

### `app/pro_router.py` (mismo proceso/puerto que el anterior, pero separado del señuelo)

| Ruta | Clasificación | Control de acceso real |
|---|---|---|
| `POST /pro/internal/log-poll` | operational real | Bearer token validado contra `log_export_stream.authenticate_consumer` (DB), feature-gate PRO `LOG_EXPORT`, rate limit, 404 en cualquier fallo (no filtra existencia de la cuenta) — **correcto** |
| `POST /pro/internal/log-token/refresh` | operational real | Rotación de refresh token validada contra DB — **correcto** |

Excluidas explícitamente del logging/scoring de honeypot y del esquema OpenAPI público
(`app/honeypot_public.py:194-196`) — documentado y correcto.

### `app/panel_mvp.py` (puerto 9001, interno) — 90 rutas

Ya inventariadas por prefijo en `documentation/NOC-001-AUDITORIA-ARQUITECTURA.md` §5
(`/dashboard/*` 64, `/admin/*` 6, `/pro/*` 5, `/api/*` 3, resto 5). Todas son **admin real**,
protegidas por `_PanelAuthMiddleware` (cookie de sesión HMAC) excepto `/health`, `/ready`,
`/login`, `/logout` (`_PANEL_AUTH_BYPASS`). Sin cambios respecto a esa auditoría.

## 2. Hallazgo — `/health`, `/ready`, `/version` en el puerto público filtran estado real

**Esto contradice la documentación existente.** `documentation/README.md` y
`documentation/ops/README.md` afirman: *"La API pública mantiene su superficie `/health` señuelo
... los chequeos reales de salud y disponibilidad viven detrás de los servicios internos"* — y
`CLAUDE.md` (escrito en el `/init` inicial de este repo, basándome en esa documentación sin
verificar el código) repite esa afirmación. **El código dice lo contrario.**

`app/honeypot_public.py:47` importa `from app import health as _health` — el **mismo** módulo
(`app/health.py`) cuyo propio docstring dice *"consumed by the FastAPI route handlers in
honeypot_public.py"*. Las rutas públicas (`app/honeypot_public.py:2587-2604`):

- `GET /health` → `_health.liveness()` → `{"status": "ok"}`. Inocuo (no revela nada), pero no es
  decoy: es la misma función real que usaría cualquier healthcheck interno.
- `GET /ready` → `_health.readiness(DB_PATH)` → ejecuta `SELECT 1 FROM alembic_version LIMIT 1`
  contra la base de datos real y devuelve `{"status": "ok"|"degraded", "checks": {"database": ...}}`
  con **503 real** si la base de datos está caída — a cualquier cliente anónimo de Internet.
- `GET /version` → `_health.version_info()` → devuelve `APP_VERSION`, `APP_ENV`, `BUILD_SHA`,
  `BUILD_TIME` reales, leídos de variables de entorno — el SHA exacto de commit desplegado,
  públicamente, sin autenticación.

Ninguna de las tres rutas distingue monitor/atacante vía `_is_monitor(request)` (a diferencia de
`/v1/auth/token`, `/v1/account`, `/v1/keys`, que sí lo hacen). El panel interno (`app/panel_mvp.py`)
tiene **su propio** `/health`/`/ready` basados en `app/status_checks.py` — un módulo distinto,
más detallado (revela incluso `database_path` y la revisión de Alembic actual) pero correctamente
confinado a `127.0.0.1`. El problema no es que exista un chequeo real — es que **el mismo tipo de
chequeo real está expuesto sin ninguna protección en el puerto de Internet**.

En Traefik (`compose/docker-compose.prod.yml`), el router `hp-health` solo cubre
`Path(/health) || Path(/status)` — **`/ready` y `/version` ni siquiera reciben el tratamiento
especial de "monitor"**; caen en el router genérico `hp-api`, exactamente como cualquier otra
ruta señuelo, pero devolviendo datos reales.

**Impacto**: un atacante anónimo puede (a) confirmar el SHA de commit exacto desplegado — recon
de alto valor para buscar vulnerabilidades conocidas de esa versión — y (b) sondear si la base de
datos está degradada, sin autenticación y sin que esto se trate como señal de ataque más allá de
`kind="health"` en el log (`app/honeypot_public.py:2356-2358`).

**Corregido en este PR** (autorizado explícitamente, fuera del alcance original de auditoría):
`/ready` y `/version` en `app/honeypot_public.py` ya no llaman a `app/health.py`. Pasan a
devolver una respuesta señuelo con la misma forma pero sin datos reales — `/ready` siempre 200
con un `checks`/`latency_ms` fabricado, `/version` solo expone `version`/`service` (sin
`build_sha`/`build_time`/`env`). `/health` no se tocó: `liveness()` ya era inocuo (`{"status":
"ok"}`, nada que filtrar). `app/health.py` queda reservado para el panel interno y
`scripts/check_app_ready.py`, que nunca lo exponen por HTTP público.

Verificado con `TestClient` contra `app/honeypot_public.py` tras migrar un DB temporal:
`GET /ready` → `200 {"status": "ok", "checks": {"database": "ok"}, "latency_ms": 5}` siempre,
independientemente del estado real de la DB; `GET /version` → `200 {"version": "1.0.0",
"service": "platform-api"}`, sin `build_sha`/`env`/`build_time`.

## 3. Hallazgo — `/pro/analytics/*` es un endpoint administrativo real alcanzable con un secreto de cebo

**Este es el hallazgo más serio de la auditoría.** `/pro/analytics/endpoints`, `/interest`,
`/fingerprinting` y `/overview` (`app/honeypot_public.py:4299-4388`) son reales: exigen
`require_admin_secret`, comprueban la feature PRO `ANALYTICS`
(`_require_feature(licensing.Feature.ANALYTICS, ...)` → 404 si no está licenciada) y devuelven
datos agregados reales calculados sobre la tabla `events` real vía `api_modular.analytics_*`.

El problema está en qué acepta `require_admin_secret` (`app/honeypot_public.py:1323-1338`):
valida la cabecera `X-Admin-Secret` contra `_issued_lookup(conn, "admin_secret", adm)`, que
comprueba únicamente si ese valor existe **en algún momento** en la tabla `issued_secrets` con
`kind="admin_secret"` — **sin comprobar a quién se le emitió ni por qué**.

La única función que escribe filas con `kind="admin_secret"` es `_get_or_create_secret()`
(`app/honeypot_public.py:1229-1246`), llamada desde el propio flujo de cebo de
`/backup/download` (`app/honeypot_public.py:4149`) para fabricar un `ADMIN_SECRET=adm_xxxx`
determinista (`sha256(actor_id | "admin_secret" | HP_SEED)`) **dentro de un archivo de backup
falso que se le entrega al atacante como señuelo**.

Es decir: **el mismo secreto que el honeypot fabrica y regala a un atacante como cebo de
"backup filtrado" es válido para autenticarse en un endpoint PRO real de analítica**. La cadena
de ataque completa:

1. El atacante dispara el señuelo `GET /backup/download/{backup_id}` → recibe
   `ADMIN_SECRET=adm_<hash>` en el cuerpo de la respuesta (texto plano, pensado para parecer una
   filtración de `.env`).
2. El atacante reenvía ese mismo valor como cabecera `X-Admin-Secret` a
   `GET /pro/analytics/overview`.
3. `require_admin_secret` lo acepta (es una fila real en `issued_secrets`).
4. Si la instancia tiene la feature PRO `ANALYTICS` activa, el atacante recibe analítica real:
   métricas de qué endpoints está tocando, su propia puntuación de "interés", y datos de
   fingerprinting — **inteligencia operativa del propio honeypot, filtrada al atacante que
   está siendo observado**.

Agravante: a diferencia de `/internal/reload`, `/internal/migrate` o `/internal/config` (que sí
llaman a `_set_hp_event(..., trap_flags=[...])` y `_bump_actor(...)` para registrar el intento
como señal de ataque), los handlers de `/pro/analytics/*` **no registran ningún evento de
honeypot** — una explotación exitosa de esta cadena no queda marcada como actividad sospechosa en
el dashboard, más allá de la entrada de log genérica `kind="probe"`.

**Alcance real del impacto**: requiere que la instancia tenga PRO + la feature `ANALYTICS`
activa (`_require_feature` devuelve 404 en instancias CORE o sin esa feature) — no afecta a
despliegues sin PRO, pero sí a cualquier instancia PRO con analítica habilitada, que es
presumiblemente la mayoría de los despliegues comerciales.

**Corregido en este PR** (autorizado explícitamente, fuera del alcance original de auditoría):
nueva función `require_internal_admin_token()` (`app/honeypot_public.py`) que valida la cabecera
`X-Admin-Secret` por comparación de tiempo constante (`hmac.compare_digest`) contra
`HP_PANEL_TOKEN` — el mismo secreto real que ya usa el panel — y **nunca** consulta
`issued_secrets`. Las 4 rutas `/pro/analytics/*` pasan a depender de esta función en vez de
`require_admin_secret`. `require_admin_secret` **no se tocó** y sigue protegiendo `/admin/secrets`
exactamente igual que antes — esa ruta es un señuelo encadenado legítimo (entrega más secretos
falsos de "vault"/"root" tras recibir uno válido) y debía seguir aceptando secretos de cebo.

Verificado con un secreto de cebo real, emitido directamente vía
`_get_or_create_secret(conn, "attacker-actor-1", "admin_secret", "adm")` (simulando exactamente
lo que recibiría un atacante en `/backup/download`):

| Ruta | Con el secreto de cebo | Antes del fix |
|---|---|---|
| `GET /pro/analytics/overview` | **401 Unauthorized** | 200 con datos reales |
| `GET /admin/secrets` | 200 (sin cambios — señuelo intacto) | 200 (igual) |
| `GET /pro/analytics/overview` con `HP_PANEL_TOKEN` real | Pasa la auth (404 solo por falta de licencia PRO/ANALYTICS en el entorno de prueba) | N/A |

## 4. Resumen de controles de acceso efectivos (no solo ocultación)

| Mecanismo | ¿Protege de verdad? |
|---|---|
| `include_in_schema=False` (ocultar de OpenAPI) | No es control de acceso — solo oculta de la documentación. Confirmado en código: varias rutas con esto activado son decoy correctamente controladas por otros medios (`/v1/admin/*`). La propia intención original de `/pro/analytics/*` lo trataba como si bastara (hallazgo §3) — ya corregido con un control de acceso real propio. |
| `require_bearer` / `require_backup_token` / `require_api_key` contra `issued_secrets` | Correcto **cuando** el endpoint es señuelo (el objetivo es que el atacante pueda "entrar" y seguir siendo observado). Nunca debe gatear un endpoint real — por eso `/pro/analytics/*` pasó a `require_internal_admin_token` en vez de reutilizar este mecanismo. |
| `require_admin_secret` | Correcto para lo que protege hoy (`/admin/secrets`, señuelo encadenado). Ya no protege ningún endpoint real — ese era el problema del hallazgo §3, corregido. |
| `require_internal_admin_token` (nuevo) | HMAC de tiempo constante contra `HP_PANEL_TOKEN`; nunca consulta `issued_secrets`. Protege `/pro/analytics/*`. |
| Cookie de sesión HMAC del panel (`_PanelAuthMiddleware`) | Correcto para su propósito actual; limitaciones ya documentadas como riesgos R3/R4 en NOC-001 (token único compartido, sin RBAC). |
| Bearer token validado contra DB en `pro_router.py` | Correcto — modelo de auth independiente del señuelo, diseñado para esto. |
| Binding `127.0.0.1` (panel) | Correcto para el panel. El puerto público no tiene binding equivalente, pero ya no expone estado real por ello (hallazgo §2, corregido). |

## 5. Criterios de aceptación

- [x] Existe matriz de rutas con clasificación public-decoy/admin/operational — sección 1.
- [x] Se identifican controles de acceso efectivos, no solo ocultación OpenAPI — sección 4,
      fundamentada en los hallazgos de las secciones 2 y 3.
- [x] Se crean hallazgos de seguridad — secciones 2 y 3, ambos verificados leyendo el código del
      handler, no solo el decorador o el nombre de la ruta.

## 6. Pruebas

Esta Issue empezó como auditoría pura, pero los dos hallazgos se corrigieron en la misma rama
tras autorización explícita. Verificación realizada:

1. **Suite completa**: la rama de NOC-002 (PR #63) ya versiona `tests/`; se tomó prestado
   temporalmente ese directorio (`git checkout noc-002-functional-test-baseline -- tests/`),
   se ejecutó la suite completa contra el código ya corregido de esta rama, y se descartó antes
   de este commit (no se añade `tests/` a esta PR — eso sigue siendo responsabilidad de #63):
   ```bash
   python -m pytest tests/ -q
   # 1017 passed, 1 skipped, 2 xfailed   (idéntico al baseline de NOC-002 — sin regresiones)
   ```
2. **Smoke test dirigido** (`TestClient` contra `app/honeypot_public.app`, DB temporal migrada
   con `alembic upgrade head`), ningún test existente cubre estas rutas, así que se verificó a
   mano:
   - `GET /health` → `200 {"status": "ok"}` (sin cambios).
   - `GET /ready` → `200 {"status": "ok", "checks": {"database": "ok"}, "latency_ms": 5}` siempre.
   - `GET /version` → `200 {"version": "1.0.0", "service": "platform-api"}`, sin `build_sha`/`env`/`build_time`.
   - Un secreto de cebo real, emitido vía `_get_or_create_secret(conn, "attacker-actor-1", "admin_secret", "adm")`
     (igual que recibiría un atacante en `/backup/download`):
     - `GET /pro/analytics/overview` con ese secreto → **401** (antes: 200 con datos reales).
     - `GET /admin/secrets` con ese mismo secreto → **200**, payload de señuelo sin cambios — la
       cadena de engaño sigue intacta.
     - `GET /pro/analytics/overview` con `HP_PANEL_TOKEN` real → pasa la autenticación (404 solo
       por falta de licencia PRO/ANALYTICS en el entorno de prueba, esperado).

## 7. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: corrige dos vulnerabilidades reales activas en el código actual (secciones 2 y
  3) — fuga de estado real por `/ready`/`/version` públicos, y bypass de autenticación de
  `/pro/analytics/*` vía secreto de cebo. Ningún otro endpoint señuelo se modificó;
  `require_admin_secret` y la cadena `/admin/secrets` quedan exactamente igual.
- **Compatibilidad**: ningún llamador legítimo depende del contrato roto — se verificó que
  `app/panel_mvp.py` calcula su propia analítica PRO en proceso (no llama a
  `/pro/analytics/*` por HTTP) y que `app/honeypot_monitor.py` excluye explícitamente `/pro/*`
  de sus comprobaciones; ningún test existente cubre estas rutas (confirmado por búsqueda en el
  código de los tests de la rama de NOC-002).
- **Despliegue**: sin cambios de infraestructura; requiere que `HP_PANEL_TOKEN` esté configurado
  en el entorno de la app pública igual que ya lo está para el panel (mismo `.env.prod`,
  variable ya compartida entre ambos servicios vía `env_file`).
- **Rollback**: revertir este commit restaura el comportamiento anterior (incluidas ambas
  vulnerabilidades) — aceptable como rollback de emergencia, pero no recomendado dado que
  reabriría los dos hallazgos.
