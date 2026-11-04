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
| Admin secretos/infra lure | `/admin/secrets`, `/infra/vault`, `/cloud/metadata` | public-decoy | Sin auth real; devuelven datos fabricados de alta tentación |
| Legacy admin (oculto) | `/v1/admin/login`, `/v1/admin/status`, `/v1/admin/rotate`, `/v1/export/users`, `/v1/export/audit` | public-decoy | `require_bearer` (igual que el resto); verificado — correctamente señuelo a pesar del nombre |
| **Health** | `/health`, `/ready`, `/version` | **operational real** (ver hallazgo §2) | **Ninguno** — sin auth, sin distinción monitor/atacante |
| Health (señuelo) | `/status` | public-decoy | Correcto: jitter + actor tracking, sin datos reales |
| **PRO analytics** | `/pro/analytics/endpoints`, `/interest`, `/fingerprinting`, `/overview` | **admin real** (ver hallazgo §3) | `require_admin_secret` — **efectivo solo en apariencia** (ver hallazgo §3) |

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

**No corregido en este PR** (fuera de alcance de una Issue de auditoría) — recomendación: que
`/ready` y `/version` del puerto público dejen de usar `app/health.py` y pasen a devolver una
respuesta señuelo equivalente a `/status`, reservando `app/health.py` para el panel/healthchecks
internos exclusivamente.

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

**No corregido en este PR** (fuera de alcance de una Issue de auditoría) — recomendación: que
`require_admin_secret` valide contra un espacio de secretos administrativos real y separado del
de cebo (p. ej. comparando contra un secreto de proceso/instalación, no contra `issued_secrets`),
o que `/pro/analytics/*` se mueva a `app/pro_router.py` (que ya tiene un modelo de auth real
independiente del señuelo) en vez de vivir directamente en `app/honeypot_public.py`.

## 4. Resumen de controles de acceso efectivos (no solo ocultación)

| Mecanismo | ¿Protege de verdad? |
|---|---|
| `include_in_schema=False` (ocultar de OpenAPI) | No es control de acceso — solo oculta de la documentación. Confirmado en código: varias rutas con esto activado son decoy correctamente controladas por otros medios (`/v1/admin/*`), pero **ninguna ruta depende de esto como único control** salvo quizá la intención original de `/pro/analytics/*`, que sí lo trata como si fuera suficiente (hallazgo §3). |
| `require_bearer` / `require_backup_token` / `require_api_key` contra `issued_secrets` | Correcto **cuando** el endpoint es señuelo (el objetivo es que el atacante pueda "entrar" y seguir siendo observado). Incorrecto cuando protege un endpoint real (hallazgo §3). |
| `require_admin_secret` | Mismo problema que arriba — ver hallazgo §3. |
| Cookie de sesión HMAC del panel (`_PanelAuthMiddleware`) | Correcto para su propósito actual; limitaciones ya documentadas como riesgos R3/R4 en NOC-001 (token único compartido, sin RBAC). |
| Bearer token validado contra DB en `pro_router.py` | Correcto — modelo de auth independiente del señuelo, diseñado para esto. |
| Binding `127.0.0.1` (panel) | Correcto, es la única protección real de `/health`/`/ready` del panel — pero nótese que **no existe binding equivalente para el puerto público**, de ahí el hallazgo §2. |

## 5. Criterios de aceptación

- [x] Existe matriz de rutas con clasificación public-decoy/admin/operational — sección 1.
- [x] Se identifican controles de acceso efectivos, no solo ocultación OpenAPI — sección 4,
      fundamentada en los hallazgos de las secciones 2 y 3.
- [x] Se crean hallazgos de seguridad — secciones 2 y 3, ambos verificados leyendo el código del
      handler, no solo el decorador o el nombre de la ruta.

## 6. Pruebas

Auditoría pura — no se ha modificado ningún archivo de `app/`. No se reclama ejecución de la
suite de tests como evidencia de esta Issue: esta rama parte de `main`, donde `tests/` no está
versionado todavía (pendiente de NOC-002/PR #63), igual que se documentó en NOC-004.

## 7. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: esta Issue no cambia comportamiento — documenta dos hallazgos reales (secciones
  2 y 3) que **siguen activos en el código actual** y afectan a cualquier instancia desplegada
  hoy. Se recomienda tratarlos como su propia Issue de corrección, priorizada, no como parte del
  trabajo de migración de NOC-006 en adelante.
- **Compatibilidad/Despliegue/Rollback**: no aplica — ningún archivo de aplicación fue modificado.
