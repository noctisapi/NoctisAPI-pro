# hp-app Container Workflow

This repo packages both the public honeypot API (`app/honeypot_public.py`) and the internal admin panel (`app/panel_mvp.py`) into a single Docker image. Docker Compose drives each environment while Alembic manages the SQLite schema.

## Repository Layout

- `docker-compose.yml`  thin wrapper that reuses the dev stack so `docker compose ...` works without extra flags.
- `compose/docker-compose.dev.yml`  local developer stack with reload + automatic migrations.
- `compose/docker-compose.prod.yml`  production stack (migrate, app, admin, nginx reverse proxy).
- `compose/nginx/nginx.conf`  TLS-terminating reverse proxy with `/api/` rate limiting.
- `migrations/`, `alembic.ini`  database migrations executed via Alembic.
- `backup_sqlite.sh` + `ops/cron/yourapp-backup`  host-side backup automation (14-day retention).
- `.env.dev` / `.env.prod.example`  environment defaults (set both `HP_DB_PATH` and `DATABASE_URL`).
- `Makefile`  common Docker/Alembic targets.

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

Both script and cron file accept overrides via `DATA_VOLUME`, `BACKUP_DIR`, `APP_DB_PATH`, and `KEEP_DAYS`.

## Production Image Build & Push (GHCR)

Authenticate once:

```
echo "$GHCR_TOKEN" | docker login ghcr.io -u <ORG> --password-stdin
```

Build and publish:

```
VERSION=0.1.0
ORG=<ORG>
docker build -t ghcr.io/$ORG/hp-app:$VERSION .
docker tag ghcr.io/$ORG/hp-app:$VERSION ghcr.io/$ORG/hp-app:latest
docker push ghcr.io/$ORG/hp-app:$VERSION
docker push ghcr.io/$ORG/hp-app:latest
```

## VPS Deployment

See `documentation/ops/vps/DEPLOY.md` for a step-by-step production runbook.

Recommended layout:

```
/opt/hp-app/
+-- compose/
   +-- docker-compose.prod.yml
   +-- nginx/
       +-- nginx.conf
       +-- certs/{fullchain.pem,privkey.pem}
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
   - `HP_PUBLIC_BASE_URL=<https://public-domain>` (used in download URLs exposed by the honeypot API)
   - `HP_GEOIP_DB=/app/data/GeoLite2-Country.mmdb`
   - `HP_SEED=<long random secret>` (stable seed for actor ids + secrets)
   - `HP_CAMPAIGN_MIN_FEATURES=4`
   - `HP_CAMPAIGN_MIN_INTERSECTION=3`
   - `HP_CAMPAIGN_MIN_JACCARD=0.4`
   - `HP_CAMPAIGN_MAX_SESSIONS=5`
   - `HP_CAMPAIGN_PATH_NGRAM_TOP_K=12`
   - `HP_CAMPAIGN_PATH_TOP_K=10`
   - `HP_CAMPAIGN_ACTOR_LIMIT=200`
2. Provide TLS files in `compose/nginx/certs/` (`fullchain.pem`, `privkey.pem`) and adjust `server_name` inside `compose/nginx/nginx.conf`.
3. Run:

```
cd /opt/hp-app
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod pull
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod up -d
```

The production compose file defines four services:

- `migrate`  runs `alembic upgrade head` and must finish successfully before others start.
- `app`  FastAPI service whose Docker healthcheck runs `python scripts/check_app_ready.py`.
- `admin`  `app/panel_mvp.py` served via Uvicorn on port 9001 and only reachable through the tunnel/reverse proxy.
- `nginx`  TLS termination + reverse proxy with `limit_req` (10 req/s, burst 20) on `/api/`.

SQLite lives in the `hp_prod_data` volume mounted at `/data`. Nginx publishes 80/443 directly. All traffic to `/api/` is rate limited per-client IP, and the real `/health` + `/ready` endpoints stay confined to the admin service (tunneled/localhost only).

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



