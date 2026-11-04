# Staging environment

An isolated, disposable environment for smoke-testing a branch before it goes anywhere near
production. It shares nothing with production or dev:

| | dev | staging | prod |
|---|---|---|---|
| Compose file | `compose/docker-compose.dev.yml` | `compose/docker-compose.staging.yml` | `compose/docker-compose.prod.yml` |
| Env file | `.env.dev` | `.env.staging` | `.env.prod` |
| Volumes | `hp_dev_data`, `hp_dev_myapp` | `hp_staging_data`, `hp_staging_myapp` | `hp_prod_data`, `hp_prod_myapp` |
| App port | `8000` (all interfaces) | `127.0.0.1:8200` | behind Traefik (`80`/`443`) |
| Admin port | `127.0.0.1:9001` | `127.0.0.1:9201` | `127.0.0.1:9001` |
| Domain / TLS | none | none (loopback only) | `HP_PUBLIC_HOST` + Let's Encrypt |
| Secrets | your own local values | synthetic placeholders from `.env.staging.example` | real production secrets |

Staging never runs Traefik and is never published on anything but `127.0.0.1` — there is no
public domain to misconfigure, by construction.

## Bring it up

```bash
cp .env.staging.example .env.staging   # first time only; values are already synthetic
docker compose -f compose/docker-compose.staging.yml --env-file .env.staging up -d --build
```

This builds the image from your current working tree (not a published GHCR tag), runs
migrations, then starts `app` on `http://127.0.0.1:8200` and the admin panel on
`http://127.0.0.1:9201` (login token: `HP_PANEL_TOKEN` from `.env.staging`).

Verify it came up:

```bash
curl -s http://127.0.0.1:8200/health
curl -s http://127.0.0.1:9201/ready
```

## Tear it down

```bash
docker compose -f compose/docker-compose.staging.yml --env-file .env.staging down -v
```

The `-v` flag also removes `hp_staging_data` and `hp_staging_myapp` — staging state is meant to
be thrown away, not preserved across runs. Omit `-v` if you want the SQLite data to survive a
restart during one testing session.

## Isolation guarantees

- **No shared secrets**: `.env.staging` is a separate file from `.env.dev`/`.env.prod`; the
  committed `.env.staging.example` only contains synthetic placeholder values (never copy a real
  `HP_SEED`, `HP_PANEL_TOKEN`, or license key into it).
- **No shared volumes**: `hp_staging_data`/`hp_staging_myapp` are distinct named volumes from
  both `hp_dev_*` and `hp_prod_*` — starting staging can never read or corrupt dev or prod data.
- **No shared domain**: staging has no Traefik service and is bound to `127.0.0.1` only, so it
  can never be reached from outside the host, let alone under a production hostname.
- **No PRO license by default**: staging runs CORE-only unless you point `LICENSE_KEY` /
  `PRO_BACKEND_URL` at a test license of your own.

## CI validation

`.github/workflows/tests.yml` validates all three compose files (`dev`, `prod`, `staging`) with
`docker compose config --quiet` on every push and pull request — this catches YAML/interpolation
errors without needing to actually build or run any of the stacks in CI.
