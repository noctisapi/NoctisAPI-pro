# NoctisAPI Pro

> A professional-grade deception platform with a realistic honeypot API, behavioral actor profiling, and a full PRO feature set — built for security teams that need more than just logging.

NoctisAPI Pro extends the open-source Core with cases workflow, campaign intelligence, file pipeline simulation, and advanced analytics. Every component is designed for safe, non-executing attacker interaction while capturing rich telemetry for threat analysis.

---

## Key Features

### Core (always available)
- **Realistic API surface** — synthetic public API with staged responses and consistent fake data to fool scanners and persistent attackers
- **Actor profiling** — every IP is tracked, scored, and progressed through behavioral stages
- **Session tracking** — multi-step interactions grouped into sessions with stage progression
- **API Modular** — configure per-endpoint behavior (enabled, response mode, richness level, fixed status)
- **Endpoint analytics** — hit patterns, interest scoring, and actor fingerprinting
- **API availability monitoring** — continuous health checks from the admin panel
- **GeoIP enrichment** — country flags and ISO codes via MaxMind GeoLite2 (optional)
- **Bulk actor management** — archive, soft-delete, restore, or purge actors in bulk
- **Docker + Traefik** — production-ready compose stack with automatic TLS via ACME

### PRO (license required)
- **Cases workflow** — triage and track attacker activity as structured investigation cases
- **Campaigns explorer** — group actors into campaigns, visualize behavioral clusters, trigger recompute
- **Replay / evidence linkage** — attach session replay and event evidence to cases
- **Advanced scoring** — extended behavioral scoring with PRO heuristics
- **File upload simulation pipeline** — simulate file upload endpoints and capture attacker-supplied payloads safely
- **API Mutation** — vary responses over time (daily/weekly rotation) to confuse automated scanners
- **Smart Rules** — conditional per-endpoint overrides by path pattern, method, or user agent

---

## Screenshots

### Dashboard
![Dashboard](Readme_images/screenshot-dashboard.png)

### Actors
![Actors](Readme_images/screenshot-actors.png)

### Campaigns (PRO)
![Campaigns](Readme_images/screenshot-campaigns.png)

### API Modular Config
![Config](Readme_images/screenshot-config.png)

---

## Architecture

NoctisAPI Pro runs as two services sharing a single SQLite database via a Docker volume:

```
┌─────────────────────────────────────────────────────┐
│                   Docker Network                    │
│                                                     │
│  ┌─────────────────────┐   ┌───────────────────┐   │
│  │   Public API (app)  │   │  Admin Panel      │   │
│  │   FastAPI · :8000   │   │  FastAPI · :9001  │   │
│  │   Internet-facing   │   │  Internal only    │   │
│  └────────┬────────────┘   └────────┬──────────┘   │
│           │                         │               │
│           └──────────┬──────────────┘               │
│                      │                              │
│              ┌───────▼────────┐                     │
│              │  SQLite (WAL)  │                     │
│              │  /data/*.db    │                     │
│              └────────────────┘                     │
└─────────────────────────────────────────────────────┘
         ▲
  Traefik (TLS termination, port 443)
```

- **Public API** (`app/honeypot_public.py`) — attacker-facing endpoints, port 8000
- **Admin Panel** (`app/panel_mvp.py`) — internal dashboard, port 9001, SSH-tunnel only
- **SQLite WAL** — `busy_timeout=5000` + retry logic for concurrent access safety

---

## Repository Structure

```
app/               Core services (public API, admin panel, monitor, health)
templates/         Jinja2 HTML templates for the admin panel
static/            CSS and JS assets
migrations/        Alembic database schema migrations
compose/           Docker Compose files (dev + prod)
ops/               Deployment scripts, crons, systemd unit
documentation/     Detailed docs and runbooks
scripts/           Utility and maintenance scripts
Readme_images/     Screenshots for this README
```

---

## Quick Start — Development

```bash
# 1. Clone
git clone https://github.com/0x-unkwn0wn/noctisapi-pro
cd noctisapi-pro

# 2. (Optional) Add GeoIP — place GeoLite2-Country.mmdb in data/

# 3. Start dev stack
docker compose -f compose/docker-compose.dev.yml up --build
```

| Service | URL |
|---|---|
| Public API (Swagger) | `http://127.0.0.1:8000/docs` |
| Admin Panel | `http://127.0.0.1:9001` |

The dev stack runs a one-shot database migrator before starting services. SQLite is stored automatically in the `hp_dev_data` Docker volume.

---

## Production Deployment

See [`documentation/ops/vps/DEPLOY.md`](documentation/ops/vps/DEPLOY.md) for the full step-by-step guide.

```bash
# 1. Clone to server
git clone https://github.com/0x-unkwn0wn/noctisapi-pro /opt/noctisapi-pro
cd /opt/noctisapi-pro

# 2. Configure environment
cp .env.prod.example .env.prod
# Edit .env.prod — see Environment Variables below

# 3. Build and start
docker build -t ghcr.io/0x-unkwn0wn/noctisapi-pro:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

---

## Accessing the Admin Panel

The admin panel is **not publicly exposed**. Access it via SSH tunnel:

```bash
# On your local machine:
ssh -L 9001:127.0.0.1:9001 user@your-server-ip

# Then open:
http://localhost:9001
```

---

## Environment Variables

See `.env.prod.example` for the full annotated reference.

| Marker | Meaning |
|---|---|
| `✔ FIXED` | Pre-configured for the Docker Compose network — do not change |
| `← YOU MUST CHANGE THIS` | Must be set to your own values before deploying |

**Key variables to set:**

| Variable | Description |
|---|---|
| `HP_PUBLIC_HOST` | Your public domain (e.g. `api.example.com`) |
| `HP_PUBLIC_BASE_URL` | Full public URL of the honeypot API |
| `ACME_EMAIL` | Email used for Let's Encrypt TLS certificate |
| `HP_SEED` | Long, stable random secret — used to derive actor IDs |

> **Important:** `HP_SEED` must never change after first run. Changing it invalidates all existing actor IDs.

---

## PRO Licensing

PRO features are enforced through the separate PRO backend. Without backend-validated licensing, the instance runs in Core mode with all PRO features disabled.

**Recommended configuration:**

| Variable | Description |
|---|---|
| `LICENSE_KEY` | Your PRO license key (`sk_live_...`) |
| `PRO_BACKEND_URL` | License validation endpoint |
| `LICENSING_PINNED_PUBLIC_KEY_PATH` | Path to pinned RSA public key PEM (default: `/app/app/licensing_server_public_key.pem`) |
| `INSTANCE_ID_PATH` | Stable installation identifier (default: `/var/lib/myapp/instance_id`) |
| `HP_PRO_LEASE_CACHE_PATH` | Signed lease cache path (default: `/var/lib/myapp/pro_lease_cache.json`) |

**Hardening:**
- Public keys are loaded from pinned file paths only
- Lease JWS is always verified locally with the pinned key
- Offline grace period is bounded by a client-side constant — not configurable via env
- If the lease expires and the backend is unreachable, the app falls back to Core mode

**Debugging license state:**
```bash
# Via admin API:
GET /admin/license

# Via container shell:
python /app/scripts/print_licensing_identity.py
```

**Stable host fingerprint across container rebuilds:**
```bash
# Option A — set directly:
INSTANCE_FINGERPRINT_SHA256=<64-char hex>

# Option B — mount host machine-id:
# Mount /etc/machine-id → /etc/host-machine-id
HP_HOST_MACHINE_ID_PATH=/etc/host-machine-id
```

---

## Notes

- Do not commit `.env.prod` or `GeoLite2-Country.mmdb` — both are in `.gitignore`
- `HP_SEED` must be a long, stable random secret — changing it breaks existing actor IDs
- `HONEYPOT_MONITOR_BASE_URL=http://app:8000` is already hardcoded in the prod compose file — do not set it in `.env.prod`
- Manual override of PRO tier is disabled — licensing is backend-validated only

---

## Use Cases

- **Threat intelligence** — profile automated scanners, credential stuffers, and targeted attackers
- **Deception in depth** — deploy alongside real services to detect lateral movement and recon
- **Campaign tracking** — group attacker clusters and visualize campaign evolution over time
- **Incident response** — link attacker sessions to cases and export evidence
- **Research** — study attacker tooling, timing, and TTPs in a safe, isolated environment

---

## Open Source Core

The open-source Core version (without PRO features) is available at:
[github.com/0x-unkwn0wn/noctisapi-core](https://github.com/0x-unkwn0wn/noctisapi-core)

---

## License

[Apache-2.0](LICENSE)
