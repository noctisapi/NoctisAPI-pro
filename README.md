# ShadowAPI

ShadowAPI is a compact deception platform that exposes a realistic public API surface and an internal admin panel for observing, scoring, and grouping attacker behavior. It is designed for safe, non-executing interaction while providing rich telemetry for analysis.

## What?s Included
- Core (always on): public ShadowAPI honeypot API, internal/admin decoys, GeoIP flags, availability monitoring, basic admin (actors, sessions, API health), basic scoring + stages, bulk actor management, retention pruning, backup script, Docker + Traefik deploy
- Pro (paid): cases workflow, campaigns explorer + recompute, replay/evidence linkage, advanced scoring, file upload + analysis simulation pipeline

## Licensing
The app supports automatic PRO licensing via an external licensing server.

Recommended configuration:
- `LICENSE_KEY=sk_live_...` (end-user input)
- `LICENSING_URL=https://licensing.example.com`
- Pin the licensing server RSA public key (PEM):
  - `LICENSING_PINNED_PUBLIC_KEY_PATH=/app/app/licensing_server_public_key.pem` (default in image), or
  - `LICENSING_PINNED_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY----- ..."`
- Persist a stable installation identifier:
  - `INSTANCE_ID_PATH=/var/lib/myapp/instance_id` (default; mount a persistent volume at `/var/lib/myapp`)
- Optional tuning:
  - `LICENSING_HTTP_TIMEOUT_SECONDS=10` (default)
  - `LICENSING_MIN_RECHECK_SECONDS=30` (default)
  - `HP_ENFORCE_LICENSE=1` to fail startup if licensing is invalid or the decision is `DENY` (default `0` = degrade to CORE)
  - `HP_LICENSE_LIMITED_BEHAVIOR=core|exit` (default `core`)
  - `HP_LICENSE_DENY_BEHAVIOR=exit|disable` (default `disable`)

The client computes a best-effort host fingerprint and sends its SHA-256 hex (64 chars). If you want a fully stable host-locked fingerprint across container rebuilds, set `INSTANCE_FINGERPRINT_SHA256` (64 hex) or mount the host machine-id into the container (for example mount `/etc/machine-id` to `/etc/host-machine-id` and set `HP_HOST_MACHINE_ID_PATH=/etc/host-machine-id`).

Debugging:
- `GET /admin/license` includes a `client_identity` object with `instance_id` and `instance_fingerprint_sha256` so you can reconcile what the app is sending with what the licensing server expects.
- Or run `python /app/scripts/print_licensing_identity.py` inside the container.

Legacy/manual override:
- `HP_LICENSE_TIER=core|pro` is still supported, but is ignored when the runtime licensing manager is enabled.

## Repository Layout
- `app/` — core services (public API, admin panel, monitor, health)
- `templates/`, `static/` — UI and assets
- `migrations/` — Alembic schema
- `compose/` — dev/prod Docker Compose
- `ops/` — deployment scripts and utilities
- `documentation/` — detailed docs and runbooks

## Quick Start (Dev)
```bash
cp .env.dev .env.dev
docker compose -f compose/docker-compose.dev.yml up --build
```

Open (default dev ports):
- Public API: `http://127.0.0.1:8000/docs`
- Admin panel: `http://127.0.0.1:9001`
If you override ports in Compose, use your configured values.

Notes:
- The dev stack runs a one-shot migrator before starting services.
- SQLite is stored in the `hp_dev_data` volume.

## Production
See `documentation/ops/vps/RUNBOOK.md` for a step‑by‑step VPS deployment with Traefik + ACME and GHCR.

## Notes
- Do not commit real secrets or GeoLite2 database files.
- Use `.env.prod` on the server and keep it out of Git.
- For admin views, set `HONEYPOT_PUBLIC_BASE_URL=https://<public-domain>` and `HONEYPOT_MONITOR_BASE_URL=http://traefik:8081`.
