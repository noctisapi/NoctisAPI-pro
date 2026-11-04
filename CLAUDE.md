
# CLAUDE.md — NoctisAPI PRO

Guidance for Claude Code working in this repository. **Read this file and the assigned GitHub Issue before editing.** This file describes the **current implementation** where stated; GitHub Issues and accepted ADRs specify approved **target migrations**. Do not assume target features already exist.

## Mission and architectural boundaries

Evolve NoctisAPI PRO into **Managed PRO 1.0**: one isolated VPS/data store per customer, public decoy API on an authorized custom domain, protected customer Security Console, automated deployment, managed feature entitlements, and a **separate internal** Noctis Control Center.

**Do not build a shared multi-tenant application or centralize attack telemetry.** Preserve the existing self-hosted deployment unless an explicit, approved Issue changes it.

Target migrations (not claims of current state):

- Traefik Docker Provider + socket mount → **Traefik File Provider, no Docker socket**. Restricted Socket Proxy is a documented contingency only, not a requirement.
- SSH-tunnel-only admin access → per-deployment **Cloudflare Tunnel + Access**, verified at origin; never expose the admin port publicly.
- Shared `HP_PANEL_TOKEN` → individual sessions, backend RBAC, audit logs.
- Customer-visible PRO activation → operator-managed, authenticated entitlements; preserve signed-license self-hosted behavior. **No universal `LICENSE_DISABLED` bypass.**
- Manual deployment → reproducible dedicated VPS deployments and a separate private Control Center.

Architecture decisions: consult `documentation/adr/0001-*.md`, `0002-*.md`, `0003-*.md`, and `documentation/NOC-004-MAPA-MIGRACION.md` **when present**. Verify their actual contents and whether they supersede this summary.

## GitHub Issue → PR workflow

1. Identify the **real GitHub Issue number/URL** (a `NOC-###` prefix is only a planning identifier). Read scope, dependencies, acceptance criteria, and relevant code/tests.
2. Check current `main` and open PRs. **Do not implement an Issue whose required dependency is not merged**, unless explicitly authorized to create a stacked PR.
3. For an independent Issue, branch from updated `main`; use a dedicated branch and **one reviewable PR per Issue**. For explicitly approved stacked PRs, base on the predecessor branch, make the PR base explicit, and verify the base after predecessor merges; never assume GitHub retargets correctly.
4. Implement only the Issue. Run relevant tests, record commands/results, and document migration, compatibility, security impact and rollback where applicable.
5. Creating a branch, commits, push, and PR is authorized for the assigned Issue. **Do not merge**, deploy, close the Issue, edit real DNS, purchase resources, or execute destructive operations without explicit approval.
6. Stop on failed tests, unmet acceptance criteria, missing permissions, uncertain dependencies, or security conflicts. Never report unrun tests as passing.
7. After an approved migration is integrated, update architectural documentation so it reflects the new current state. Do not claim a PR is integrated merely because it exists.

**Prohibited:** direct commits to `main` for new work; force-push/reset-hard; committing or logging secrets; unrelated refactors; changing production or customer data without approval. Historical direct commits are not precedent for new Issues.

**Definition of done:** scoped change; acceptance criteria verified; relevant tests and negative security tests passed or limitations stated; no secrets/public admin exposure; documentation/rollback provided; PR reviewable. Project status `Done` and Issue closure require verified integration.

## Security invariants

- The **public API is attacker-facing**; treat its input and headers as untrusted. Keep real administrative routes and monitoring isolated. Hiding a route from OpenAPI is **not** an access control.
- Never expose Docker socket/API, database, private health endpoints, panel port, or Control Center to the public Internet.
- Do not trust `X-Forwarded-*`, `Host`, PROXY Protocol, or user identity headers without explicit validation and known trusted-hop configuration.
- Access/edge identity does not replace **backend authorization**. Use least privilege, fail closed, and audit sensitive actions.
- Do not allow attacker-controlled requests to reach internal management networks or unrestricted outbound destinations.
- Isolate customers' deployments, credentials and data. Control Center must not have direct access to each customer's honeypot database.
- Preserve deception/telemetry behavior while protecting genuine PRO/control endpoints. Require backups and rollback for database or infrastructure changes.

## Current code map

- Public FastAPI: `app/honeypot_public.py` (port 8000); admin FastAPI: `app/panel_mvp.py` (port 9001). Entrypoints are `main.py` and `main_panel.py` (preserve structured-logging initialization).
- Shared SQLite (`HP_DB_PATH` / `DATABASE_URL`) across two processes, WAL + busy timeout/retries. **Never assume in-memory state is shared**. Migrations: Alembic (`migrations/`); startup `migrate` service, app expects schema at head.
- Middleware order (outer → inner): `RequestTimeoutMiddleware` → `ReverseProxyMiddleware` → `log_all_requests` → `CORSMiddleware` → routes. Trust/origin logic: `app/trusted_proxy.py`, `app/reverse_proxy.py`, `app/server_config.py`.
- `app/pro_router.py` serves **real**, non-decoy routes in the public app; currently excluded from deception telemetry/OpenAPI. Audit access independently before changing routing.
- Catalog: `app/catalog/`; persisted instance state: `app/instance_config/` + `app/legacy_config_adapter.py`; provider: `app/runtime_provider.py`; resolver: `app/endpoint_resolver.py`; response generation: `app/response_factory/`.
- `RuntimeConfigProvider` is the effective runtime source with cache (default TTL 60s), refresh on custom-template fingerprint changes and a default fallback on error. Review these behaviors before changing it; tests should isolate provider instances.
- **Legacy and new request paths coexist**: `app/api_modular.py` controls legacy response mode/mutation/rules; `EndpointResolver` supplies semantic endpoint IDs; `ResponseFactory` handles only migrated endpoints, others use handlers in `honeypot_public.py`. Check both paths before editing endpoints.
- Actor classification: `app/stage/`; threat `Stage` (0–8), Automated/Targeted confidence, and per-request `attack_phase` are **different concepts**. Preserve their semantics.
- Existing PRO licensing: `honey_licensing/`, `app/pro_license.py`, `app/license_runtime.py`, `app/licensing*.py`, currently RS256-signed backend-validated leases and pinned public key. Basic per-endpoint configuration works without PRO; mutation rules and other advanced features are gated. The licensing server is separate. Do not remove this current behavior as an incidental change.
- Public `/health` is a **decoy**. Real `/health`, `/ready`, `/version` live on the admin side; Docker readiness uses `scripts/check_app_ready.py`. Never leak real health state via the decoy API.

## Commands (verify Makefile before use)

```bash
python main.py                         # public API
python main_panel.py                   # admin panel
make dev-up && make dev-logs           # development stack
make dev-down
make prod-pull && make prod-up         # production: NEVER run without deployment approval
make db-upgrade                        # migration: use only in authorized environment
make db-revision MSG="description"     # create Alembic revision
python -m pytest tests/ -q             # full tests
python -m pytest tests/test_health.py -v
```

`pytest` may need separate installation; there is no verified repo-wide lint/formatter command in the supplied baseline. Report environment failures instead of silently skipping checks.

## Operational traps

- **Never change `HP_SEED` on an existing deployment:** actor/session identity continuity depends on it.
- `PUBLIC_BASE_URL` drives OpenAPI server URLs; legacy `HP_PUBLIC_BASE_URL` is used for response download URLs. They are distinct. In the existing Docker deployment the legacy URL needs a Docker-reachable service hostname, not `127.0.0.1`.
- Admin `127.0.0.1:9001` + SSH tunnel is **current/interim**, not the managed target. Never expose it directly through Traefik.
- Env-dependent tests use cache-reset patterns (see `tests/test_reverse_proxy.py`). Add equivalent cache cleanup for new cached configuration.
- Check `documentation/README.md` and existing handlers before assuming an endpoint is migrated to `ResponseFactory`.

## Instruction conflicts

Follow mandatory security requirements and approved Issue scope, preserve unrelated existing behavior, and use this file as repository context.

If two instructions cannot be reconciled safely, **stop and report the exact conflict**. Never quietly interpret architecture goals as permission to bypass tests, controls, or approvals.
