# ShadowAPI Container Workflow

This repo packages both the public ShadowAPI honeypot API (`app/honeypot_public.py`) and the internal admin panel (`app/panel_mvp.py`) into a single Docker image. Docker Compose drives each environment while Alembic manages the SQLite schema.

## Repository Layout

- `docker-compose.yml`  thin wrapper that reuses the dev stack so `docker compose ...` works without extra flags.
- `compose/docker-compose.dev.yml`  local developer stack with reload + automatic migrations.
- `compose/docker-compose.prod.yml`  production stack (migrate, app, admin, traefik reverse proxy).
- `migrations/`, `alembic.ini`  database migrations executed via Alembic.
- `backup_sqlite.sh` + `ops/cron/yourapp-backup`  host-side backup automation (14-day retention).
- `.env.dev` / `.env.prod.example`  environment defaults (set both `HP_DB_PATH` and `DATABASE_URL`).
- `Makefile`  common Docker/Alembic targets.

## Licensing

Feature availability is controlled by backend-validated PRO licensing.

Recommended configuration:
- `LICENSE_KEY=sk_live_...`
- `PRO_BACKEND_URL=https://pro-backend.example.com`
- Pin the licensing server RSA public key (PEM):
  - `LICENSING_PINNED_PUBLIC_KEY_PATH=/app/app/licensing_server_public_key.pem` (default in image)
- `INSTANCE_ID_PATH=/var/lib/myapp/instance_id` (default)
- `HP_PRO_LEASE_CACHE_PATH=/var/lib/myapp/pro_lease_cache.json`

The app computes a host fingerprint and sends its SHA-256 hex. Mount a persistent Docker volume at `/var/lib/myapp` so `INSTANCE_ID_PATH` survives container recreation.

Debugging:
- The admin service exposes `GET /admin/license` (bound to `127.0.0.1` in production) with backend license status plus `client_identity` (`instance_id`, `instance_fingerprint_sha256`).
- You can also run `python /app/scripts/print_licensing_identity.py` inside a container.

Hard requirement:
- PRO operations are enabled only with a valid signed lease (`RS256`) verified with the pinned licensing public key.
- Campaign recompute runs locally in the app; backend is only used for `POST /v1/licenses/validate`.
- Offline grace is capped by a client code constant (`CLIENT_CAP_SECONDS`), not environment configuration.

Manual tier override is disabled. Without backend-validated licensing, PRO remains disabled.

## Local Development

1. Install Docker Engine + Compose plugin.
2. Copy `.env.dev` if you need overrides (`HP_DB_PATH=/data/honeypot.db`, etc.).
3. Run `make dev-up` (or `docker compose up -d --build`) to run the migrator and start API + admin with `--reload`.
4. Visit http://localhost:8000 (API) and http://localhost:9001 (admin).
5. `make dev-logs` / `make dev-down` (or `docker compose logs`, `docker compose down`) for maintenance.

The dev stack mount-binds the repo into `/app`, exposes 8000/9001, reuses the `hp_dev_data` volume for SQLite, and adds a container healthcheck that runs `python scripts/check_app_ready.py`.

## Database Migrations (Alembic)

- Apply the latest migrations locally: `make db-upgrade` (wrapper for `alembic upgrade head`).
- Generate a new revision: `make db-revision MSG="short description"`.
- Inspect history: `make db-history`.

`DATABASE_URL` (and optionally `HP_DB_PATH`) must point at the SQLite file the containers use (`/data/honeypot.db`). Every Compose stack now starts with a short-lived `migrate` service that runs `alembic upgrade head`; the API refuses to serve traffic until the `alembic_version` table matches the most recent revision, and the internal admin readiness endpoint surfaces that state.

## Backups

- `backup_sqlite.sh` runs on the host (no container shell required). It uses a disposable `alpine:3` container to execute `sqlite3 .backup`, writes the snapshot to `./backups`, and prunes files older than `KEEP_DAYS` (default 14).
- Copy `ops/cron/yourapp-backup` to `/etc/cron.d/yourapp-backup`, adjust the paths (e.g., `BACKUP_DIR=/var/backups/honey-app` and script path `/opt/hp-app/backup_sqlite.sh`), and cron will invoke the backup daily at 02:15 UTC.
 - Set `VERIFY_INTEGRITY=1` to run `PRAGMA integrity_check` on each backup file.

Both script and cron file accept overrides via `DATA_VOLUME`, `BACKUP_DIR`, `APP_DB_PATH`, and `KEEP_DAYS`.

## Data Retention (TTL)

Use `scripts/prune_retention.py` to delete old rows from high-volume tables.

Defaults (days):

- `HP_RETENTION_EVENTS_DAYS=30`
- `HP_RETENTION_SESSIONS_DAYS=30`
- `HP_RETENTION_STEPS_DAYS=30`
- `HP_RETENTION_CHECKS_DAYS=14`
- `HP_RETENTION_TOKENS_DAYS=90`
- `HP_RETENTION_JOBS_DAYS=30`

Retention is enabled by default via cron (`HP_RETENTION_ENABLE=1`). Set `HP_RETENTION_ENABLE=0` to disable.

Dry-run:

```
python /opt/hp-app/scripts/prune_retention.py --db /data/honeypot.db --dry-run
```

Apply:

```
python /opt/hp-app/scripts/prune_retention.py --db /data/honeypot.db
```

## Actor Merge (UA Family)

When you switch actor identity to `IP + UA family`, you may want to retroactively merge existing actors.

Script:

- `scripts/merge_actors_by_ua_family.py`

What it does:

- Rewrites `actor_id` across `events`, `sessions`, `tokens`, `issued_secrets`, `case_actors`, and `campaign_actor_links`.
- Rebuilds `actors` and `actor_fingerprints` with merged rows.
- Deduplicates `case_actors` and `campaign_actor_links`.

Usage (run inside the app container so it can access `/data/honeypot.db`):

```
# dry run
docker exec compose-app-1 python /app/scripts/merge_actors_by_ua_family.py \
  --db /data/honeypot.db --seed "<HP_SEED>" --dry-run

# apply
docker exec compose-app-1 python /app/scripts/merge_actors_by_ua_family.py \
  --db /data/honeypot.db --seed "<HP_SEED>"
```

Notes:

- Use the same `HP_SEED` that the app uses in production.
- The merge is not reversible; take a backup before applying.

## Production Image Build & Push (GHCR)

Authenticate once:

```
echo "$GHCR_TOKEN" | docker login ghcr.io -u <ORG> --password-stdin
```

Build and publish:

```
VERSION=0.1.0
ORG=<ORG>
docker build -t ghcr.io/$ORG/shadowapi-pro:$VERSION .
docker tag ghcr.io/$ORG/shadowapi-pro:$VERSION ghcr.io/$ORG/shadowapi-pro:latest
docker push ghcr.io/$ORG/shadowapi-pro:$VERSION
docker push ghcr.io/$ORG/shadowapi-pro:latest
```

## VPS Deployment

See `documentation/ops/vps/DEPLOY.md` for a step-by-step production runbook.

Recommended layout:

```
/opt/hp-app/
+-- compose/
   +-- docker-compose.prod.yml
+-- backup_sqlite.sh
+-- .env.prod
```

Steps:

1. Copy/clone the repo and duplicate `.env.prod.example` to `.env.prod`, then fill in:
   - `APP_ENV=prod`
   - `APP_VERSION=<semver matching pushed image>`
   - `HP_DB_PATH=/data/honeypot.db`
   - `DATABASE_URL=sqlite+pysqlite:////data/honeypot.db`
   - `LOG_LEVEL=info`
   - `HP_PUBLIC_BASE_URL=<https://public-domain>` (used in download URLs exposed by the ShadowAPI honeypot API)
   - `HP_GEOIP_DB=/app/data/GeoLite2-Country.mmdb`
   - `HP_SEED=<long random secret>` (stable seed for actor ids + secrets)
   - `HP_CAMPAIGN_MIN_FEATURES=4`
   - `HP_CAMPAIGN_MIN_INTERSECTION=3`
   - `HP_CAMPAIGN_MIN_JACCARD=0.4`
   - `HP_CAMPAIGN_MAX_SESSIONS=5`
   - `HP_CAMPAIGN_PATH_NGRAM_TOP_K=12`
   - `HP_CAMPAIGN_PATH_TOP_K=10`
   - `HP_CAMPAIGN_ACTOR_LIMIT=200`
2. Ensure `.env.prod` includes `HP_PUBLIC_HOST` and `ACME_EMAIL` for Traefik.
3. Run:

```
cd /opt/hp-app
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod pull
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod up -d
```

The production compose file defines four services:

- `migrate`  runs `alembic upgrade head` and must finish successfully before others start.
- `app`  FastAPI service whose Docker healthcheck runs `python scripts/check_app_ready.py`.
- `admin`  `app/panel_mvp.py` served via Uvicorn on port 9001 and bound to `127.0.0.1` (SSH tunnel).
- `traefik`  TLS termination + reverse proxy with ACME.

SQLite lives in the `hp_prod_data` volume mounted at `/data`. Traefik publishes 80/443 directly. The real `/health` + `/ready` endpoints stay confined to the admin service, while the public API keeps its decoy `/health`.

## Make Targets

| Target        | Description |
|---------------|-------------|
| `make dev-up` | Build + start the dev stack with reload + automatic migrations |
| `make dev-logs` | Tail dev logs |
| `make dev-down` | Stop dev stack |
| `make prod-pull` | Pull production images (reads `.env.prod`) |
| `make prod-up` | Apply production stack |
| `make prod-logs` | Tail prod logs |
| `make db-upgrade` | Run `alembic upgrade head` against the current `DATABASE_URL` |
| `make db-revision MSG="..."` | Create a new Alembic revision with a custom message |
| `make db-history` | Show verbose Alembic history |

All production commands expect to execute on the server that hosts `.env.prod` and the TLS assets.



## Health & Readiness

- The honeypot (app/honeypot_public.py) exposes only a fake /health endpoint for external actors so it never leaks real system state.
- The internal admin API (app/panel_mvp.py) serves the real /health and /ready endpoints, which verify SQLite connectivity and Alembic migrations.
- Docker healthchecks for the app container call `python scripts/check_app_ready.py`, reusing status_checks.ensure_ready() to test the DB directly instead of hitting HTTP endpoints.
- The admin console exposes a API Health page (see the navigation link) that pings the public /health endpoint from the server side and lets operators trigger manual re-checks.



