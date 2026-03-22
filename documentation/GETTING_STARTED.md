# NoctisAPI — Getting Started

> Minimum viable guide for new customers. Covers installation, first run, and what to expect.

---

## What is NoctisAPI?

NoctisAPI is a **deception API** — a realistic-looking REST service that silently tracks, profiles, and scores anyone who probes it.

Instead of blocking attackers, NoctisAPI lets them in. It responds with convincing fake data (tokens, credentials, user records, config files) while building a detailed profile of every actor: what they scanned, what they tried to exploit, how far they got, and how their behavior correlates with other actors you have seen.

**What you get:**
- A public-facing honeypot API with 50+ convincing endpoints (auth, admin, CI/CD, cloud, file upload, console access)
- An admin panel where you observe actors, review sessions, manage investigations, and configure endpoint behavior
- Structured, enriched logs suitable for SIEM ingestion

**Core vs Pro:**

| | Core | Pro |
|---|---|---|
| Honeypot API (all endpoints) | ✓ | ✓ |
| Actor tracking & scoring | ✓ | ✓ |
| Admin panel (actors, sessions) | ✓ | ✓ |
| Modular endpoint config | ✓ | ✓ |
| Cases (investigation dossiers) | — | ✓ |
| Campaigns (attack correlation) | — | ✓ |
| Session replay | — | ✓ |
| API mutation (response drift) | — | ✓ |
| Smart rules engine | — | ✓ |
| Analytics endpoints | — | ✓ |
| File pipeline | — | ✓ |

---

## How It Works

```
Internet → [ your-api.example.com ] → NoctisAPI public container (port 8000)
                                              ↓
                                      Logs every request
                                      Scores the actor
                                      Returns fake-but-convincing data
                                              ↓
                                      SQLite database (shared volume)
                                              ↓
[ you ] → [ 127.0.0.1:9001 ] → Admin panel → See actors, sessions, cases
```

1. **Actor identification** — every source IP gets a stable, deterministic actor ID (seeded by `HP_SEED`). No cookies, no sessions needed.
2. **Scoring** — each endpoint hit scores points. Recon endpoints score low (1–6 pts). Credential endpoints score medium (5–8 pts). Exploit attempts (shell, upload, root access) score high (10–20 pts).
3. **Staging** — actors advance through 5 stages (0–4) as their score grows. Stage determines what "capabilities" they appear to gain.
4. **Sessions** — activity is grouped into sessions (15-minute gap = new session). Each session captures every request and response.
5. **Campaigns (Pro)** — actors with overlapping endpoint patterns are automatically correlated into campaigns. One campaign = one coordinated attack pattern.

---

## Installation

### Prerequisites

- Linux server (tested: Ubuntu 22.04 / Debian 12)
- Docker + Docker Compose v2
- A domain name pointing to your server (for TLS)
- Port 80 and 443 open inbound

### Step 1 — Pull the image

```bash
docker login ghcr.io
# Use the credentials from your license email
docker pull ghcr.io/0x-unkwn0wn/noctisapi-pro:latest
```

### Step 2 — Create your `.env` file

```bash
cp .env.prod.example .env
```

Edit `.env` and fill in **at minimum** these values:

```env
# Required — keep this stable, never change after first run
HP_SEED=<long-random-string>          # e.g. openssl rand -hex 32

# Your public domain
HP_PUBLIC_HOST=your-api.example.com
HP_PUBLIC_BASE_URL=https://your-api.example.com

# TLS (Let's Encrypt)
ACME_EMAIL=ops@example.com

# Admin panel token (auto-generates if empty, but set one)
HP_PANEL_TOKEN=<strong-secret>

# Pro license (path inside the container — do not change)
HP_OFFLINE_LICENSE_PATH=/var/lib/myapp/license.json
HP_DEPLOYMENT_ID=prod-001             # Pick a stable name for this deployment
```

### Step 3 — Install your license (Pro only)

Copy the `license.json` file you received by email into the data volume directory before first start:

```bash
# Create the volume directory if it doesn't exist
mkdir -p /opt/noctisapi/myapp

# Copy license file
cp ~/license.json /opt/noctisapi/myapp/license.json
```

In your `docker-compose.prod.yml`, the volume should map to that directory:

```yaml
volumes:
  - /opt/noctisapi/myapp:/var/lib/myapp
```

### Step 4 — Start the stack

```bash
docker compose --env-file .env -f compose/docker-compose.prod.yml up -d
```

The first run:
1. Applies database migrations
2. Downloads the GeoIP database (if `MAXMIND_ACCOUNT_ID` is set)
3. Starts the public API on port 8000 (behind Traefik on 443)
4. Starts the admin panel on port 9001 (localhost only)

---

## First Run Validation

### 1. Check the public API is up

```bash
curl https://your-api.example.com/health
# Expected: {"status": "ok"}

curl https://your-api.example.com/ready
# Expected: {"status": "ok", "checks": {"database": "ok"}, "latency_ms": <int>}
```

If `/ready` returns `503` or `"status": "degraded"`, the database is not accessible. Check volume mounts.

### 2. Check the admin panel is reachable

```bash
# From the server (or via SSH tunnel)
curl http://127.0.0.1:9001/health
# Expected: {"status": "ok"}
```

Open the admin panel in your browser (via SSH tunnel):

```bash
ssh -L 9001:127.0.0.1:9001 user@your-server
```

Then visit: `http://127.0.0.1:9001`

Login with your `HP_PANEL_TOKEN`.

### 3. Verify the license (Pro)

In the admin panel, go to **Settings → License** or visit:

```
http://127.0.0.1:9001/admin/license
```

Expected:

```json
{
  "tier": "pro",
  "status": "active",
  "features": ["cases", "campaigns", "replay", "analytics", "api_mutation", "file_pipeline", "advanced_scoring"]
}
```

If you see `"tier": "core"` or a reason code like `OFFLINE_LICENSE_MISSING`, the license file is not mounted correctly (see Troubleshooting).

### 4. Trigger a test event

Hit any honeypot endpoint from your local machine:

```bash
curl https://your-api.example.com/.env
```

In the admin panel, go to **Actors**. You should see your IP as a new actor with 1 event and a score > 0.

Hit a few more endpoints:

```bash
curl https://your-api.example.com/v1/auth/token -X POST
curl https://your-api.example.com/admin
curl https://your-api.example.com/internal/config
```

Reload Actors — the score should increase and the actor should advance in stage.

---

## Understanding the Output

### Actor list

Each row in the Actors view shows:

| Field | Meaning |
|---|---|
| **Actor ID** | Stable identifier for this IP (derived from HP_SEED + IP) |
| **Stage** | 0–4. Higher = more aggressive behavior observed |
| **Score** | Cumulative suspicion score. 0–9 = noise, 10–30 = curious, 30+ = active probe, 100+ = aggressive |
| **Last Seen** | Last request timestamp |
| **Events** | Total number of requests from this actor |
| **Flags** | Trap flags triggered (recon, secrets, auth, upload, exploit) |

### Event scoring reference

| What they did | Points scored |
|---|---|
| Hit a recon endpoint (`.env`, `config.json`, swagger) | 3–6 |
| Attempted auth / posted credentials | 5–8 |
| Requested internal config or feature flags | 5 |
| Attempted console command execution | 5 |
| Attempted file upload via trap | 15 |
| Attempted root shell access | 20 |

### Session replay (Pro)

Each session shows a step-by-step timeline of every request the actor made, in order, with the full request (method, path, headers, body) and the response returned. Use this to understand exactly what an attacker was trying to do and in what order.

### Campaigns (Pro)

Campaigns group actors that share the same behavioral fingerprint — same endpoint patterns, same sequence, similar timing. One campaign typically represents:
- A single automated scanner running from multiple IPs
- A coordinated team using the same tooling
- A recurring attacker using the same playbook

Campaign score reflects duration, number of actors, stages reached, and sensitive endpoints accessed.

### Cases (Pro)

Cases are your investigation workspace. When you identify an actor or campaign worth tracking:

1. Open a case from the actor page or campaign page
2. Add actors and evidence (session replays)
3. Update status as you investigate (`open` → `monitoring` → `closed`)
4. Export as JSON or Markdown for reporting

---

## Troubleshooting

### `"status": "degraded"` on `/ready`

The container cannot read or write the database.

```bash
# Check volume mount
docker exec <container> ls -la /data/
# Should show honeypot.db

# Check permissions
docker exec <container> stat /data/honeypot.db
```

The app runs as user `10001`. The `/data` directory must be writable by that UID.

### License shows `OFFLINE_LICENSE_MISSING` or `tier: core`

The `license.json` file is not where the container expects it.

```bash
# Verify the file is mounted
docker exec <container> ls -la /var/lib/myapp/
# Should show license.json

# Verify the path env var
docker exec <container> env | grep HP_OFFLINE_LICENSE_PATH
```

If the file is there but license still shows as missing, the deployment ID may not match. Check:

```bash
docker exec <container> env | grep HP_DEPLOYMENT_ID
```

The value must match what is encoded in your `license.json`. Contact support with the `reason_code` shown in the license status response.

### No actors appearing after hitting endpoints

Check that the public container is receiving requests:

```bash
docker logs <app-container> --tail=50
```

You should see JSON log lines with `"kind": "event"` for each request. If you see nothing, Traefik may not be routing to the container. Check Traefik logs:

```bash
docker logs <traefik-container> --tail=50
```

### Admin panel shows blank / 500 error

The admin panel depends on the public API being reachable at `http://app:8000` (Docker internal). Check:

```bash
docker exec <admin-container> curl http://app:8000/health
```

If this fails, the containers are not on the same Docker network.

### Events are appearing but actor score is 0

Check that `HP_SEED` is set. Without a seed, actor IDs may not be stable.

```bash
docker exec <app-container> env | grep HP_SEED
```

### CORS errors on the landing page checkout

Set the correct domain in your `.env`:

```env
CORS_ALLOWED_ORIGINS=https://www.noctisapi.com,https://noctisapi.com
```

Then restart the container. The CORS middleware reads origins at startup.

---

## Support

If you are stuck after following this guide, email **support@unkwn0wn.com** with:

1. The output of `docker exec <container> curl http://localhost:8000/ready`
2. The output of `docker exec <container> curl http://localhost:9001/admin/license`
3. Last 50 lines of container logs: `docker logs <container> --tail=50`

Include your license ID (visible in the admin panel under Settings → License).
