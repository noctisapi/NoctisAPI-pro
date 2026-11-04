# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

NoctisAPI PRO (`Honey_app`): a honeypot platform with three runtime pieces sharing one SQLite database:

- **Public API** — `app/honeypot_public.py` (port 8000, internet-facing, decoy surface)
- **Admin panel** — `app/panel_mvp.py` (port 9001, internal only, real `/health`/`/ready`)
- **Modular catalog/runtime engine** — `app/catalog/`, `app/runtime/`, `app/runtime_provider.py`, `app/response_factory/`, `app/endpoint_resolver.py` (pure functions, no HTTP)

PRO licensing (`honey_licensing/`, `app/licensing*.py`, `app/pro_*.py`) gates advanced features; `app/api_modular.py` holds the legacy per-endpoint override engine that the modular runtime is progressively replacing.

## Commands

Entrypoints are plain Python scripts (not `uvicorn` CLI invocations) so structured logging/SIEM config runs before uvicorn starts:

```bash
python main.py          # public API, port 8000 (env: PORT)
python main_panel.py    # admin panel, port 9001 (env: PANEL_PORT)
```

Local dev stack (Docker):

```bash
make dev-up      # build + start dev stack (reload, auto-migrate)
make dev-logs
make dev-down
```

Production stack (requires `.env.prod`, copied from `.env.prod.example`):

```bash
make prod-pull    # docker compose --env-file .env.prod -f compose/docker-compose.prod.yml pull
make prod-up
make prod-logs
```

Database (Alembic, SQLite):

```bash
make db-upgrade               # alembic upgrade head
make db-revision MSG="..."    # alembic revision -m "..."
make db-history
```

Tests (pytest is installed separately — not pinned in `requirements.txt`):

```bash
python -m pytest tests/ -q                     # full suite
python -m pytest tests/test_health.py -v        # single file
python -m pytest tests/test_health.py::TestName::test_case -v   # single test
```

There is no lint/format command configured in this repo.

## Architecture

### Two FastAPI apps, one DB

The public app and admin panel are separate FastAPI processes that read/write the same SQLite file via a Docker volume (`HP_DB_PATH` / `DATABASE_URL`). SQLite is used in WAL mode with `busy_timeout` and retry logic to absorb lock contention between the two processes. Never assume single-process state — anything cached in-memory (runtime config, catalog version) must tolerate the other process changing the DB underneath it.

### Request middleware stack (`honeypot_public.py`)

Execution order, outermost to innermost:

```
RequestTimeoutMiddleware → ReverseProxyMiddleware → log_all_requests → CORSMiddleware → route handlers
```

- `app/server_config.py` — `REQUEST_TIMEOUT`/`KEEPALIVE_TIMEOUT`/`IDLE_TIMEOUT` env vars, `RequestTimeoutMiddleware`, `get_uvicorn_kwargs()`. Timeouts are tuned to stay below Cloudflare's 90s idle / 400s keepalive limits.
- `app/reverse_proxy.py` — ASGI middleware that rewrites `scope` scheme/server from `X-Forwarded-*` headers, but only for trusted proxies (`app/trusted_proxy.py`). `get_public_base_url(request)` prefers `PUBLIC_BASE_URL` env > forwarded headers > raw socket.
- `log_all_requests` sets `request.state.client_ip` and `request.state.public_base_url`, and logs every request as a scored honeypot event — except `app/pro_router.py` routes, which are explicitly excluded from honeypot telemetry/actor tracking (they're real backend endpoints embedded in the same app, not part of the deception surface).
- `PUBLIC_BASE_URL` drives the OpenAPI `servers` list; `HP_PUBLIC_BASE_URL` is legacy and only feeds `download_url` fields in responses. Don't conflate the two.

### The modular runtime (how a request becomes a fake response)

This is the layered system documented in `documentation/README.md`/`README.md` and it is the main thing to understand before touching endpoint behavior:

1. **Catalog** (`app/catalog/`) — a validated, immutable-after-load static definition of the deception surface: endpoints, endpoint groups, response profiles, security-flaw profiles, extension packs, and base templates (`ecommerce`, `corporate_saas`, built-in under `app/catalog/builtin/`). `CatalogRegistry` (`app/catalog/registry.py`) enforces cross-reference integrity; a bad catalog raises `CatalogValidationError` and the app refuses to start (fail fast, not a runtime error).
2. **Instance config** (`app/instance_config/`) — the persisted per-deployment state (active template, enabled extensions, per-endpoint overrides) adapted from legacy DB rows by `LegacyConfigAdapter` (`app/legacy_config_adapter.py`).
3. **RuntimeConfigProvider** (`app/runtime_provider.py`) — the single source of truth. Combines catalog + instance config into an `EffectiveRuntimeConfig`, cached with a TTL (`HP_RUNTIME_CACHE_TTL`, default 60s) and rebuilt when the custom-template DB fingerprint changes. All errors are swallowed with a fallback to `InstanceConfig.default()` — this provider must never raise. Access via module-level `get_runtime_config()` / `resolve_effective_endpoint()`, not by instantiating directly (except in tests, which should inject a fresh provider for isolation).
4. **EndpointResolver** (`app/endpoint_resolver.py`) — maps `(method, path)` to an `EffectiveEndpoint` via exact match first, then `{param}` pattern matching with highest-literal-segment-count winning ties. Runs independently of `app/api_modular.py`'s `resolve_request_policy()` — the two systems are not yet merged: `api_modular` controls `response_mode`/mutation/rules (legacy), `EndpointResolver` provides semantic `endpoint_id`/`operation_type` (new).
5. **ResponseFactory** (`app/response_factory/`) — generates responses for *migrated* endpoints only. Everything else still falls back to the hand-written route handlers in `honeypot_public.py`. Check `documentation/README.md`'s "Progressive ResponseFactory Rollout" section (or grep `honeypot_public.py` for the endpoint) before assuming an endpoint goes through the factory — telemetry/scoring/sessions/actor-tracking run identically on both paths, but response shape does not.
6. The admin panel surfaces all of this live at `/dashboard/api-modular` (active template/extensions, effective catalog, overrides, resolution preview, analytics, PRO-gated mutation/rule controls).

When adding or changing endpoint behavior, decide explicitly whether you're editing the catalog (new deception surface), the legacy handler in `honeypot_public.py` (still-unmigrated endpoint), or both — they are two different code paths that happen to coexist.

### Actor scoring and classification (`app/stage/`)

Two independent classifications get attached to events, and they answer different questions — don't conflate them:

- **Stage (0-8)**: cumulative threat ladder per actor, derived from an accumulated score (recon, auth activity, admin/internal access, backups/secrets, cloud-metadata/console escalation all add score). See `app/stage/threat_level.py` / `classifier.py` for the score→stage mapping (documented in `README.md`).
- **Automated vs Targeted**: a deterministic (no ML, no randomness) per-request heuristic in `app/stage/classifier.py` combining 8 normalized signals (frequency, path entropy, header shape, UA, timing vs. endpoint progression, statefulness, adaptation after errors) into `attack_confidence` + `attack_signals`.
- **attack_phase** (`recon`/`access`/`collection`/`exfiltration`/`impact`) is yet a third, per-request axis — distinct from both `Stage` and Automated/Targeted.

### Licensing (`honey_licensing/`, `app/pro_license.py`, `app/license_runtime.py`, `app/licensing*.py`)

- All features are PRO-gated: `honey_licensing/feature_flags.py` has `_CORE_FEATURES = set()` and every `Feature` enum member in `_PRO_FEATURES` (cases, campaigns, replay, advanced scoring, file pipeline, API mutation, analytics, webhooks, log export). Basic per-endpoint config (enabled, response_mode, richness_level, fixed_status) works without PRO; rule-based mutation (`Feature.API_MUTATION`) requires it.
- PRO is enabled only by a backend-validated, RS256-signed lease verified against a pinned public key (`app/licensing_server_public_key.pem`). There is no manual tier override. Offline grace is capped by a code constant, not env config.
- `app/pro_router.py` hosts real (non-deception) backend endpoints — e.g. the PRO log-export long-poll — mounted inside the public app but deliberately excluded from honeypot event logging/actor tracking and from the public OpenAPI schema. Keep that separation when adding routes there.
- The companion licensing server lives in a sibling repo (LicensingApp-ShadowAPI, runs on a local Kali box, not the VPS) — this repo is only the client side.

### Health/readiness split

The public API intentionally exposes only a fake `/health` (part of the deception surface, no real system state). Real `/health`, `/ready`, `/version` live on the admin panel only (`app/health.py`): liveness is pure, readiness does `SELECT 1 FROM alembic_version`, and Docker healthchecks call `scripts/check_app_ready.py` directly against the DB rather than over HTTP.

### Database migrations

Alembic (`migrations/`, `alembic.ini`). The compose stacks run a short-lived `migrate` service before `app`/`admin` start; the app refuses to serve until `alembic_version` matches head. Use `make db-revision MSG="..."` rather than hand-writing revision files.

### Tests

`tests/` mirrors `app/` roughly 1:1 (one test file per module). Common pattern: tests build an in-memory `sqlite3.connect(":memory:")` DB and call the module's `ensure_tables()`/`ensure_*_table()` before exercising it — don't assume a shared fixture DB. Env-dependent modules (proxy, TLS, trusted-proxy, health, server config, structured logging) use an `_EnvOverride(**kwargs)` context manager that resets module-level caches on enter/exit; when adding a new module-level cache, wire its reset into that pattern (see `tests/test_reverse_proxy.py` resetting `app.reverse_proxy._PUBLIC_BASE_URL` manually as the precedent for caches the shared `_EnvOverride` doesn't already know about).

## Operational notes worth knowing before changing related code

- `HP_SEED` must stay stable after first deploy — changing it breaks actor identity continuity across all historical sessions/events.
- `HP_PUBLIC_BASE_URL` (legacy, used in response `download_url` fields) must use the Docker service name (`http://app:8000`), not `127.0.0.1`, since it's resolved from inside the container network.
- The admin panel is bound to `127.0.0.1:9001` only in production; it's reached via SSH tunnel, never exposed through Traefik.

## Development workflow

Each GitHub Issue is implemented on its own branch and delivered as a Pull Request — never
committed directly to `main`, except when an Issue's own template explicitly has no PR
requirement (e.g. NOC-001, an audit-only Issue, already completed as a direct commit to `main`).

**Stacked branches for dependent Issues**: when an Issue's own "Dependencias" field names an
earlier Issue whose PR has not been merged into `main` yet, branch from the tip of that
predecessor's branch instead of from `main`, and open the PR against that predecessor branch
(not against `main`). This keeps one reviewable PR per Issue even when later work depends on
earlier, still-unmerged work. Merge PRs in dependency order; GitHub automatically retargets a
dependent PR's base to `main` once its predecessor branch is merged and deleted. Only branch
directly from `main` when the Issue has no unmerged dependency.

Mandatory rules:
- Read the Issue and this file before starting; work on one GitHub Issue at a time, in a
  dedicated branch (e.g. `noc-002-...`), implementing only what that Issue's own scope covers.
- Run relevant tests before every commit; document commands and results.
- Create one descriptive commit (or a small number of them) per completed Issue.
- Push the Issue's branch and open a Pull Request once its acceptance criteria are met. This is
  the unattended boundary: implementation, tests, commit, branch push, and PR creation can happen
  without waiting for approval.
- Never merge a Pull Request into `main`, deploy, or run destructive git operations
  (`git reset --hard`, `git push --force`, branch deletion) without explicit authorization.
- Never delete existing functionality without authorization.
- Do not commit secrets or production credentials.
- Do not deploy to production automatically.
- Stop and report failures before proceeding; do not silently skip a failing acceptance criterion.
- Do not start the next Issue until the current one has reached its stopping point (PR opened, or
  explicitly blocked) and has been reported.

## Target architecture constraints (NOC-004)

NoctisAPI PRO is migrating from a single self-hosted deployment to a Managed, single-tenant-per-
customer product (full rationale and alternatives in `documentation/adr/0001-*.md`,
`0002-*.md`, `0003-*.md`, and `documentation/NOC-004-MAPA-MIGRACION.md`). These constraints are
binding for every Issue in that migration (NOC-005 onward), not just the ones that created them:

- **Never drop the self-hosted path.** `compose/docker-compose.prod.yml` (today's self-hosted
  deployment) must keep working throughout the migration — no Issue may remove or break it
  without its own explicit, authorized deprecation decision.
- **Traefik discovery**: default is a static/dynamic **File Provider** config, not
  `providers.docker`. Never mount `/var/run/docker.sock` into Traefik. A Docker Socket Proxy is
  only acceptable as a documented contingency if File Provider genuinely cannot cover a case —
  and only with minimal read-only methods, a private network, and no published port (ADR 0003).
- **Console reachability**: the admin panel is reached only through a per-installation
  Cloudflare Tunnel with edge identity validation (Access) once that work lands — never by
  publishing the admin port directly, and SSH-tunnel access is an interim path, not the target
  (ADR 0002).
- **Console identity**: the shared `HP_PANEL_TOKEN` is an interim mechanism. The target is
  individual user sessions with backend-enforced RBAC and an audit log of admin actions — not a
  single shared secret (ADR 0002).
- **No universal license bypass.** "Managed Mode" must evaluate entitlements from authenticated,
  operator-deployed configuration — never a `LICENSE_DISABLED`-style flag that would also weaken
  self-hosted licensing.
- **Control Center is a separate system.** Its data model (Customer, Subscription, Deployment,
  Domain, Job, Version, InfraCost, AuditLog) must never give it direct access to a customer
  honeypot's own database, and no path may let it aggregate attacker-reachable data across
  customers (ADR 0001).