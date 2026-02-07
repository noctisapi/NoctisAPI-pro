# ShadowAPI

ShadowAPI is a compact deception platform that exposes a realistic public API surface and an internal admin panel for observing, scoring, and grouping attacker behavior. It is designed for safe, non-executing interaction while providing rich telemetry for analysis.

## What’s Included
- Public API (honeypot) with staged behavior and consistent synthetic data
- Admin panel for actors, sessions, campaigns, cases, and health monitoring
- Scoring + stage progression with replay/evidence linkage
- File upload and analysis simulation pipeline
- Availability monitoring with authenticated checks

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

Open:
- Public API: `http://127.0.0.1:8000/docs`
- Admin panel: `http://127.0.0.1:9001`

Notes:
- The dev stack runs a one-shot migrator before starting services.
- SQLite is stored in the `hp_dev_data` volume.

## Production
See `documentation/ops/vps/RUNBOOK.md` for a step‑by‑step VPS deployment with Traefik + ACME and GHCR.

## Notes
- Do not commit real secrets or GeoLite2 database files.
- Use `.env.prod` on the server and keep it out of Git.
- For admin views, set `HONEYPOT_PUBLIC_BASE_URL=https://<public-domain>` and `HONEYPOT_MONITOR_BASE_URL=http://traefik:8081`.
