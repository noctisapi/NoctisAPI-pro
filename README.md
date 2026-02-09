# ShadowAPI

ShadowAPI is a compact deception platform that exposes a realistic public API surface and an internal admin panel for observing, scoring, and grouping attacker behavior. It is designed for safe, non-executing interaction while providing rich telemetry for analysis.

## What?s Included
- Core (always on): public ShadowAPI honeypot API, internal/admin decoys, GeoIP flags, availability monitoring, basic admin (actors, sessions, API health), basic scoring + stages, bulk actor management, retention pruning, backup script, Docker + Traefik deploy
- Pro (paid): cases workflow, campaigns explorer + recompute, replay/evidence linkage, advanced scoring, file upload + analysis simulation pipeline

## Licensing
The app supports automatic PRO licensing via an external Licensing server.

LicensingApp integration (recommended):
- Set `LICENSE_KEY=sk_live_...` (end-user input).
- Set `LICENSING_URL=https://licensing.example.com`.
- Optional:
  - `FINGERPRINT_PATH=/var/lib/myapp/device_fingerprint` (default)
  - `LICENSING_HTTP_TIMEOUT_SECONDS=10` (default)
  - `LICENSING_MIN_RENEW_SECONDS=30` (default)

The app generates a UUID fingerprint once and persists it at `FINGERPRINT_PATH`. For Docker, mount a persistent volume at `/var/lib/myapp` so the fingerprint survives container recreation.

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
