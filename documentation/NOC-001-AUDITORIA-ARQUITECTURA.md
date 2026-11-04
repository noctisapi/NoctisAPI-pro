# NOC-001 — Auditoría de arquitectura y despliegue actual

Issue: [#4 NOC-001 — Auditar arquitectura y despliegue actual](https://github.com/0x-unkwn0wn/noctisapi-pro/issues/4)

**Objetivo de este informe:** inventariar la arquitectura y el despliegue actuales de NoctisAPI PRO
antes de modificar su infraestructura. Este documento es puramente descriptivo: no se ha
modificado ningún archivo de aplicación, configuración de producción, ni infraestructura
desplegada. Las referencias a `app/*` usan la forma `archivo:línea` para que cada afirmación
sea verificable directamente en el código.

---

## 1. Docker Compose

Hay tres archivos Compose:

- `docker-compose.yml` (raíz) — wrapper fino que `extends` los servicios `migrate`, `app` y `admin`
  de `compose/docker-compose.dev.yml`, reutilizando volúmenes externos nombrados
  `compose_hp_prod_data` / `compose_hp_prod_myapp`. Permite ejecutar `docker compose ...` desde la
  raíz sin flags adicionales.
- `compose/docker-compose.dev.yml` — stack de desarrollo local. Monta el repo completo (`../:/app`),
  usa `--reload`, expone `8000` y `127.0.0.1:9001`, y corre `migrate` como servicio de un solo uso
  (`alembic upgrade head`) con `depends_on: service_completed_successfully` antes de levantar
  `app`/`admin`.
- `compose/docker-compose.prod.yml` — stack de producción con cuatro servicios: `migrate`, `app`,
  `admin`, `traefik`. Usa la imagen publicada (`${HP_IMAGE}:${APP_VERSION}`), no build local.

Hardening ya presente en el servicio `app`/`admin` de producción: `user: "10001:0"`, `read_only: true`,
`tmpfs` para `/tmp` con `noexec,nosuid`, `security_opt: no-new-privileges:true`, `cap_drop: ALL`.

Artefacto suelto encontrado: `compose/nginx/` existe como directorio pero está vacío (no hay
archivos rastreados por git ni en disco). Es un remanente de una configuración anterior
(Traefik ya es el proxy actual); no afecta al despliegue pero conviene limpiarlo o documentarlo
en una Issue de housekeeping aparte.

## 2. Inventario de puertos, volúmenes y redes

### Puertos (producción, `compose/docker-compose.prod.yml`)

| Servicio | Puerto interno | Publicación en host | Notas |
|---|---|---|---|
| `traefik` | 80, 443, 8081 | `80:80`, `443:443`, `127.0.0.1:8081:8081` | 80/443 públicos; 8081 (`webinternal`) solo loopback |
| `app` | 8000 | — (`expose` only, enrutado por Traefik) | sin publicación directa al host |
| `admin` | 9001 | `127.0.0.1:9001:9001` | solo loopback; acceso real vía túnel SSH |
| `migrate` | — | — | servicio de un solo uso, sin puertos |

En desarrollo (`compose/docker-compose.dev.yml`) `app` se publica directamente en `8000:8000` (todas
las interfaces) y `admin` en `127.0.0.1:9001:9001`.

### Volúmenes

| Volumen | Tipo | Uso |
|---|---|---|
| `hp_prod_data` / `hp_dev_data` | named volume | SQLite (`/data/honeypot.db`), compartido por `migrate`, `app`, `admin` |
| `hp_prod_myapp` / `hp_dev_myapp` | named volume | `/var/lib/myapp` — `instance_id`, caché de lease PRO |
| `traefik_letsencrypt` | named volume | `/letsencrypt/acme.json` (certificados ACME) |
| `../data/siem:/var/log/noctisapi` | bind mount (solo `app`) | salida de logs SIEM a disco del host |
| `/etc/machine-id:/etc/host-machine-id:ro` | bind mount (`app`, `admin`) | fingerprint de host para licenciamiento |
| `/var/run/docker.sock:/var/run/docker.sock:ro` | bind mount (`traefik`) | Traefik Docker provider (ver riesgos, §7) |

### Redes

No hay ningún bloque `networks:` declarado en ninguno de los tres archivos Compose. Todos los
servicios (`migrate`, `app`, `admin`, `traefik`) comparten la red *bridge* por defecto que Compose
crea para el proyecto. No existe segmentación de red entre la API pública, el panel interno y
Traefik a nivel Docker — el aislamiento actual depende exclusivamente de los bindings de puerto
(`127.0.0.1:...`) y de las reglas de Traefik, no de la topología de red.

## 3. Configuración de Traefik

Definida inline como argumentos de `command:` en `compose/docker-compose.prod.yml` (no hay
`traefik.yml` ni File Provider — el *Docker provider* lee la configuración de los `labels` de cada
contenedor):

- Imagen fijada: `traefik:v2.11`.
- `--providers.docker.exposedbydefault=false` — ningún contenedor se expone salvo que declare
  `traefik.enable=true` explícitamente (lo hace `app`; `admin` no).
- Entrypoints: `web` (:80, solo redirección/ACME HTTP-01), `websecure` (:443), `webinternal` (:8081,
  publicado solo en `127.0.0.1`).
- TLS: Let's Encrypt vía `certresolver=letsencrypt`, challenge HTTP-01, email `${ACME_EMAIL}`.
- Routers sobre el servicio `app` (labels en `compose/docker-compose.prod.yml`):
  - `hp-api`: `Host(${HP_PUBLIC_HOST})` en `websecure`, con rate-limit
    `HP_PUBLIC_RATELIMIT_AVG`/`BURST` (120/240 por defecto).
  - `hp-health`: mismo host + `Path(/health, /status)`, prioridad 100, inyecta
    `X-Internal-Monitor: 1` y aplica un rate-limit distinto (30/60).
  - `hp-internal`: `PathPrefix(/)` sobre el entrypoint `webinternal` (:8081, loopback), prioridad
    120 — ruta de monitorización interna sin pasar por el dominio público.
- `admin` no tiene labels de Traefik: no es enrutado por Traefik en absoluto, solo por el
  `ports:` directo a `127.0.0.1:9001`.

## 4. Trusted proxies

Implementado en [app/trusted_proxy.py](../app/trusted_proxy.py). Resolución de IP real del cliente:

1. Si la conexión TCP directa **no** proviene de una red en `TRUSTED_PROXIES` (o, si no está
   definida, de los defaults — loopback, RFC1918, ULA; `app/trusted_proxy.py:44-53`), se descartan
   todas las cabeceras de reenvío y se devuelve la IP de socket tal cual (`app/trusted_proxy.py:185-193`).
   Se emite un `warning` si una conexión no confiable trae cabeceras de proxy (posible intento de
   spoofing).
2. Si la conexión sí viene de un proxy confiable, el orden de prioridad es:
   `CF-Connecting-IP` → `X-Forwarded-For` (recorrido derecha-a-izquierda, salta IPs confiables) →
   `X-Real-IP` → IP de socket.

**Observación:** `TRUSTED_PROXIES` no está fijado explícitamente en `.env.prod.example` revisado en
este repo; si no se define en el entorno real, se usan los defaults (RFC1918/loopback/ULA), lo cual
es correcto para el salto único Traefik→app dentro de la misma red Docker, pero **no** confía en
Cloudflare por defecto — si en algún momento se antepone Cloudflare al stack, `TRUSTED_PROXIES`
debe incluir explícitamente los rangos de Cloudflare para que `CF-Connecting-IP` sea honrado.

## 5. Inventario de rutas administrativas (`app/panel_mvp.py`)

El panel declara 90 rutas HTTP. Por prefijo:

| Prefijo | Nº rutas | Contenido |
|---|---|---|
| `/dashboard/*` | 64 | UI y API del panel: overview, actores, casos, campañas, replay, api-modular, analítica |
| `/admin/*` | 6 | Endpoints de diagnóstico/depuración (p. ej. `/admin/license`) |
| `/pro/*` | 5 | Rutas PRO (gestión de licencia, operaciones) |
| `/api/*` | 3 | API interna del panel |
| `/actor...` | 1 | Detalle de actor |
| `/`, `/login`, `/logout`, `/health`, `/ready` | 5 | Raíz, auth, salud real |

No se incluyen las rutas señuelo de `app/honeypot_public.py` (puerto 8000) porque pertenecen a la
superficie de engaño pública, no a rutas administrativas reales.

Todas las rutas del panel (excepto `/health`, `/ready`, `/login`, `/logout` —
`_PANEL_AUTH_BYPASS`, `app/panel_mvp.py:93`) pasan por `_PanelAuthMiddleware`, que exige una
cookie de sesión válida (ver §6).

## 6. Autenticación y licenciamiento

### Autenticación del panel

- Token único compartido vía `HP_PANEL_TOKEN` (`app/panel_mvp.py:95`). Si no está definido, se
  genera un token aleatorio de un solo uso por proceso y se registra como `warning` en el log
  (`app/panel_mvp.py:96-103`) — aceptable para dev, **a evitar en producción** (si el proceso se
  reinicia sin `HP_PANEL_TOKEN` fijado, el token cambia y queda solo en logs).
- Login (`POST /login`, `app/panel_mvp.py:556-575`): compara el token con `hmac.compare_digest`
  (tiempo constante) y, si coincide, emite una cookie de sesión HMAC-firmada
  (`hp_panel_session`, `httponly`, `samesite=strict`, TTL 8h). `secure=False` está puesto
  explícitamente porque el panel es "localhost-only" (comentario en el propio código,
  `app/panel_mvp.py:566`) — es decir, la cookie no se marca `Secure` asumiendo que nunca viaja
  por una conexión expuesta; esto es coherente con el despliegue actual (sin Traefik, solo
  loopback + túnel SSH) pero es una suposición implícita que rompería si el panel se expusiera
  alguna vez detrás de TLS sin revisar este flag.
- No hay límite de intentos ni bloqueo tras fallos repetidos en `/login` — la única mitigación de
  fuerza bruta es el aislamiento de red (bind a `127.0.0.1`, acceso solo vía túnel SSH).
- Modelo de identidad: token único compartido, no hay usuarios ni sesiones individuales ni RBAC
  (ya cubierto como trabajo futuro en NOC-017/018/019/020 del backlog).

### Licenciamiento PRO

- Todas las funciones son PRO-gated: `honey_licensing/feature_flags.py` define `_CORE_FEATURES`
  vacío y todas las features en `_PRO_FEATURES` (`cases`, `campaigns`, `replay`,
  `advanced_scoring`, `file_pipeline`, `api_mutation`, `analytics`, `webhooks`, `log_export`).
- PRO solo se activa mediante una lease firmada RS256, validada contra la clave pública fijada
  en el propio repo (`app/licensing_server_public_key.pem`) — sin override manual de tier
  (`documentation/README.md`, sección Licensing).
- El backend de licenciamiento (`LICENSING_URL`/`PRO_BACKEND_URL`) es un servicio aparte;
  según la memoria del proyecto corre en un equipo local (Kali), no en la VPS de producción —
  esto implica una dependencia externa de disponibilidad: si ese servicio cae, el comportamiento
  depende de la gracia offline capada por constante de cliente (`CLIENT_CAP_SECONDS` en
  `app/pro_license.py`), no configurable por entorno.
- `app/pro_router.py` monta endpoints reales (no señuelo) dentro de la misma app pública
  (ej. long-poll de exportación de logs PRO), explícitamente excluidos del logging/scoring de
  honeypot y del esquema OpenAPI público — separación correcta, pero significa que `app/pro_router.py`
  comparte proceso y puerto con la superficie de engaño; un fallo de aislamiento ahí
  (ya cubierto por NOC-011) afectaría a una ruta funcional real, no solo a una decoy.

---

## 7. Riesgos y dependencias identificados

| # | Riesgo / dependencia | Evidencia | Cubierto por |
|---|---|---|---|
| R1 | Traefik monta `/var/run/docker.sock` (read-only) para su Docker provider — acceso de solo lectura al socket sigue siendo una superficie de escalada si Traefik se ve comprometido | `compose/docker-compose.prod.yml`, servicio `traefik` | NOC-008, NOC-009 (ya en backlog) |
| R2 | Sin segmentación de red Docker: `app`, `admin`, `traefik`, `migrate` comparten la red bridge por defecto del proyecto | Ningún `networks:` en los 3 compose files | NOC-011 |
| R3 | Panel usa un token único compartido sin usuarios/sesiones individuales ni RBAC, sin límite de intentos de login | `app/panel_mvp.py:95-130, 556-575` | NOC-017, NOC-018, NOC-019, NOC-020 |
| R4 | `HP_PANEL_TOKEN` sin definir genera un token efímero por proceso, solo visible en logs — fácil de desplegar accidentalmente sin token persistente | `app/panel_mvp.py:96-103` | — (no hay Issue específica; candidata a nueva Issue o a NOC-010/012) |
| R5 | Dependencia externa del backend de licenciamiento (otro repo/host) para habilitar PRO; gracia offline fija por constante de cliente, no por entorno | `documentation/README.md` (Licensing), `app/pro_license.py` | — (fuera del alcance de seguridad del proxy; relevante para NOC-039 a NOC-045, área `licensing`) |
| R6 | `TRUSTED_PROXIES` no está fijado en `.env.prod.example`; si se antepone Cloudflare al stack sin configurarlo, `CF-Connecting-IP` no será honrado (fallback a defaults RFC1918/loopback) | `app/trusted_proxy.py:44-53, 90-94`; `.env.prod.example` | NOC-010 |
| R7 | Artefacto `compose/nginx/` vacío, remanente de una configuración de proxy anterior a Traefik | `compose/nginx/` (directorio vacío) | — (housekeeping, sin Issue) |
| R8 | Push a `main` dispara automáticamente el pipeline de release (`.github/workflows/ghcr.yml`): build + push a GHCR + subida a R2 + notificación al servidor de licenciamiento de una nueva versión. El flujo de trabajo actual (desarrollo directo en `main`, un commit por Issue) implica que *cualquier* push a `main` es, en la práctica, una publicación de release — no hay una rama de integración intermedia | `.github/workflows/ghcr.yml` (`on: push: branches: [main]`) | — (ver §8, nota de proceso) |

Ninguno de estos riesgos requiere acción en el marco de NOC-001: ya están cubiertos por Issues
específicas del backlog (columna "Cubierto por"), salvo R4, R7 y R8, que no tienen Issue asociada
todavía y se documentan aquí para que se decida si abrir una nueva Issue o resolverlos como
housekeeping menor.

## 8. Nota de proceso (fuera del alcance técnico de NOC-001)

El flujo de trabajo definido en `CLAUDE.md` ("Development workflow") establece desarrollo directo
sobre `main`, un commit descriptivo por Issue completada, y prohíbe el push sin autorización
explícita. Dado R8, conviene tener presente — antes de autorizar un push — que cada push a `main`
no es solo "guardar el commit en remoto": también es, automáticamente, un trigger de release de
imagen Docker productiva y de notificación al servidor de licenciamiento. Esto no es una
contradicción con las reglas actuales (que ya exigen autorización explícita de push), pero sí un
efecto secundario a confirmar caso por caso antes de pushear cualquier commit a `main`, no solo
los que cambian código de aplicación.

## 9. Conclusión

- Se ha completado el inventario solicitado: Docker Compose, puertos/volúmenes/redes, configuración
  de Traefik, trusted proxies, rutas administrativas y autenticación/licenciamiento (§1–§6).
- Riesgos y dependencias identificados en §7, con referencia cruzada a las Issues del backlog que
  ya los cubren.
- **No se ha modificado ningún archivo de producción ni de aplicación.** Este informe es el único
  artefacto nuevo añadido por NOC-001.
