# NoctisAPI



NoctisAPI is a compact deception platform that exposes a realistic public API surface and an internal admin panel for observing, scoring, and grouping attacker behavior. It is designed for safe, non-executing interaction while providing rich telemetry for analysis.



## What?s Included

- Core (always on): public NoctisAPI honeypot API, internal/admin decoys, GeoIP flags, availability monitoring, basic admin (actors, sessions, API health), basic scoring + stages, bulk actor management, retention pruning, backup script, Docker + Traefik deploy
- Pro (paid): cases workflow, campaigns explorer + recompute, replay/evidence linkage, advanced scoring, file upload + analysis simulation pipeline



## Licensing
PRO licensing is enforced through the separate PRO backend.

Recommended configuration:
- `LICENSE_KEY=sk_live_...` (end-user input)
- `PRO_BACKEND_URL=https://pro-backend.example.com` (primary validation endpoint)
- `LICENSING_URL` – alternate backend URL used by some tooling (optional)
- Pin the licensing server RSA public key (PEM):
  - `LICENSING_PINNED_PUBLIC_KEY_PATH=/app/app/licensing_server_public_key.pem` (default in image)
- Persist a stable installation identifier:
  - `INSTANCE_ID_PATH=/var/lib/myapp/instance_id` (default; mount a persistent volume at `/var/lib/myapp`)
- Persist the signed lease cache:
  - `HP_PRO_LEASE_CACHE_PATH=/var/lib/myapp/pro_lease_cache.json`
- Telemetry/reporting (optional):
  - `HP_LICENSE_REPORT_TO_SERVER=1` to enable
  - `HP_LICENSE_REPORT_URL=https://license.unkwn0wn.com`

Advanced behavior:
- `INSTANCE_FINGERPRINT_SHA256` or `HP_HOST_MACHINE_ID_PATH` for stable fingerprint

Other environment knobs exist (actor UA mode, monitor UA, etc.) – see
`.env.prod.example` for a complete list.

The client computes a best-effort host fingerprint and sends its SHA-256 hex (64 chars). If you want a fully stable host-locked fingerprint across container rebuilds, set `INSTANCE_FINGERPRINT_SHA256` (64 hex) or mount the host machine-id into the container (for example mount `/etc/machine-id` to `/etc/host-machine-id` and set `HP_HOST_MACHINE_ID_PATH=/etc/host-machine-id`).

Debugging:
- `GET /admin/license` includes backend license status and `client_identity` (`instance_id`, `instance_fingerprint_sha256`).
- Or run `python /app/scripts/print_licensing_identity.py` inside the container.

Manual override by tier is disabled. Without backend-validated licensing, all PRO features stay disabled.

## Campaigns PRO Backend

Campaign recompute is local in the client app again.
The backend is used only for `POST /v1/licenses/validate` and returns a signed lease (`RS256`) with fields like `tier`, `exp`, `features`, `instance_id`, `fingerprint_sha256`.

Hardening:
- Public keys are loaded from pinned file paths only (`LICENSING_PINNED_PUBLIC_KEY_PATH`).
- Lease JWS is always verified locally with the pinned key.
- Offline grace is bounded by a client-side constant in code (`CLIENT_CAP_SECONDS`), not `.env`.
- If the lease is expired and the backend cannot be reached, the app falls back to `core`.


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

A sample environment file is provided at `.env.prod.example` (not gitignored) – copy it to `.env.prod` and fill in real values before deploying. The example includes all required settings and the campaign auto‑recompute variables (`HP_CAMPAIGN_AUTO_RECOMPUTE_THRESHOLD`/`_INTERVAL`).

See `documentation/ops/vps/RUNBOOK.md` for a step‑by‑step VPS deployment with Traefik + ACME and GHCR.



## Notes

- Do not commit real secrets or GeoLite2 database files.

- Use `.env.prod` on the server and keep it out of Git.

- For admin views, set `HONEYPOT_PUBLIC_BASE_URL=https://<public-domain>` and `HONEYPOT_MONITOR_BASE_URL=http://traefik:8081`.

- Other common settings you'll find in `.env.prod.example`:
  - `HP_IMAGE` to override the image registry/name
  - `HP_PUBLIC_HOST` / `HP_PUBLIC_BASE_URL` for API routing
  - `HP_ACTOR_UA_MODE` for actor identity logic (ip|family|full)
  - `HONEYPOT_MONITOR_UA` to whitelist healthcheck user‑agents
  - `HP_GEOIP_DB`, `HP_SEED`, retention/backup/auto‑recompute tuning

