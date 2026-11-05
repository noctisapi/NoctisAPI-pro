# NoctisAPI PRO — VPS Deployment (Ubuntu 22.04+)

Concrete, repeatable deployment flow for a single VPS with Docker + Traefik (ACME TLS).

---

## 1. System prep

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release ufw git
```

Install Docker + Compose plugin:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER   # reconnect SSH after this
```

Firewall (open SSH + web only, keep admin port local):

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
# The admin port (9001) is never published on any interface, not even
# 127.0.0.1 — it has no firewall rule because it has nothing to allow or
# block from the outside. It's reached only through the cloudflared sidecar
# (NOC-016); see step 8.
```

---

## 2. Clone the repo

```bash
sudo mkdir -p /opt/hp-app
sudo chown -R $USER:$USER /opt/hp-app
git clone <REPO_URL> /opt/hp-app
cd /opt/hp-app
```

---

## 3. Configure `.env.prod`

```bash
cp .env.prod.example .env.prod
nano .env.prod
```

**Values you MUST change** (marked `← YOU MUST CHANGE THIS` in the example):

| Variable | Description |
|---|---|
| `HP_PUBLIC_HOST` | Your public API domain (e.g. `api.example.com`) |
| `HP_ADMIN_HOST` | Your admin panel domain (e.g. `admin.example.com`) |
| `CLOUDFLARE_TUNNEL_TOKEN` | Per-installation tunnel token from the Cloudflare Zero Trust dashboard — see step 8 |
| `HP_PUBLIC_BASE_URL` | Full public URL (e.g. `https://api.example.com`) |
| `HONEYPOT_PUBLIC_BASE_URL` | Same as above |
| `ACME_EMAIL` | Your email for Let's Encrypt |
| `HP_SEED` | Long random secret — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |

**Values that are pre-configured and MUST NOT be changed** (marked `✔ FIXED`):

| Variable | Value | Why fixed |
|---|---|---|
| `HONEYPOT_MONITOR_BASE_URL` | `http://app:8000` | Internal Docker network — admin talks to app container directly |
| `HONEYPOT_MONITOR_UA` | `HealthCheck/1.0,curl/` | Monitor user-agent list |
| `HP_DB_PATH` | `/data/honeypot.db` | Container volume path |
| `DATABASE_URL` | `sqlite+pysqlite:////data/honeypot.db` | Container volume path |
| `HP_ASN_RESOLVER_URL` | `https://ipwho.is/{ip}` | HTTP geo/asn resolver template; must contain `{ip}` |
| `HP_BACKUP_TOKEN_MIN_STAGE` | `1` | Threat level required before `/v1/keys` emits `backup_token` |
| `HP_LICENSE_MODE` | `offline` | Licensing mode |
| `INSTANCE_ID_PATH` | `/var/lib/myapp/instance_id` | PRO licensing persistence |
| `HP_OFFLINE_LICENSE_PATH` | `/var/lib/myapp/license.json` | PRO license file path |

> Note: `HONEYPOT_MONITOR_BASE_URL` is also hardcoded in `compose/docker-compose.prod.yml`
> under the `admin` service environment, which takes precedence over `.env.prod`.

---

### 3b. DNS for `HP_PUBLIC_HOST` (NOC-024)

Any domain or client-authorized subdomain works — `HP_PUBLIC_HOST` isn't
restricted to a particular zone. Point it at this VPS **before** the first
deploy, so Traefik's ACME HTTP-01 challenge (`compose/docker-compose.prod.yml`)
succeeds on first boot instead of retrying in its logs:

- **A record** (IPv4) and/or **AAAA record** (IPv6) at your DNS provider,
  resolving `HP_PUBLIC_HOST` directly to this VPS's public IP.
- If your registrar only offers a CNAME (delegating to another hostname
  you control), that hostname must itself resolve to this VPS's IP —
  the HTTP-01 challenge connects to whatever address the name ultimately
  resolves to, on port 80.
- **No CDN or reverse proxy in front of `HP_PUBLIC_HOST`** (e.g. Cloudflare's
  orange-cloud proxying) — the challenge must reach Traefik directly.
  `HP_ADMIN_HOST` is the opposite case: it's *supposed* to go through
  Cloudflare (the Tunnel, step 8), which is why it isn't in this section.

Verify DNS and the issued certificate after deploying:

```bash
python scripts/verify_domain.py --host <HP_PUBLIC_HOST> --expected-ip <this VPS's public IP>
```

Exits non-zero with a specific reason (doesn't resolve, resolves
somewhere else, certificate invalid or expiring soon) rather than a raw
error — safe to wire into your own deploy pipeline as a post-deploy gate.
Re-run it any time you suspect DNS or renewal drifted; `--skip-tls` checks
DNS alone, `--no-ip-check` is for domains that aren't expected to resolve
straight to this VPS (e.g. spot-checking `HP_ADMIN_HOST`'s own resolution
through Cloudflare).

---

## 4. Prepare data directories

```bash
# Database and app state (created by Docker volumes — just ensure parent exists)
mkdir -p /opt/hp-app/data

# SIEM events — bind-mounted from container, must be owned by container user (uid 10001)
mkdir -p /opt/hp-app/data/siem
chown -R 10001:0 /opt/hp-app/data/siem
chmod 775 /opt/hp-app/data/siem
```

After deploy, SIEM security events are written to:

```bash
tail -f /opt/hp-app/data/siem/events.json
```

See [`docs/siem_integration.md`](../../../docs/siem_integration.md) for Filebeat/Fluentbit integration.

---

## 5. Geo resolver (for country flags)

The app resolves country data through an HTTP ASN resolver. By default it uses `https://ipwho.is/{ip}`; override it if you run your own service.

```bash
mkdir -p /opt/hp-app/data
# Optional override:
export HP_ASN_RESOLVER_URL=https://ipwho.is/{ip}
```

---

## 6. Build the Docker image

```bash
cd /opt/hp-app
docker build -t ghcr.io/0x-unkwn0wn/noctisapi-pro:latest .
```

Or pull from the registry if you have access:

```bash
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml pull
```

---

## 7. First deploy

```bash
cd /opt/hp-app
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

Verify the public API is up:

```bash
curl -sS https://<your-api-host>/health
```

---

## 8. Access the admin panel

The admin port is never published on any interface. It's reached exclusively
through a per-installation Cloudflare Tunnel (`cloudflared`, NOC-016) — without
one configured, there is no public route to it at all.

One-time setup, per installation:

1. In the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com/),
   go to **Networks → Tunnels → Create a tunnel**, choose the "Cloudflared"
   connector type, and name it (e.g. `hp-app-prod`).
2. Add a **Public Hostname** for the tunnel: hostname = your `HP_ADMIN_HOST`
   (from `.env.prod`), service = `HTTP`, URL = `admin:9001` (the Docker
   service name — `cloudflared` reaches it over `net-internal`, never the
   public internet).
3. Copy the tunnel token Cloudflare shows you and set it as
   `CLOUDFLARE_TUNNEL_TOKEN` in `.env.prod`.
4. (Recommended, NOC-017) Add a [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/)
   application in front of that same Public Hostname (**Access → Applications
   → Add an application → Self-hosted**), with whatever identity policy fits
   your plan (email allowlist, SSO, MFA). This gives you two independent
   layers: Access decides who reaches the tunnel at Cloudflare's edge, and
   the panel itself *cryptographically verifies* the Access JWT against
   Cloudflare's JWKS before serving anything (`app/cloudflare_access.py`) —
   it never just trusts a `Cf-Access-*` header because it's present. Copy the
   Application's **Audience (AUD) Tag** and your team domain into `.env.prod`:
   - `CF_ACCESS_TEAM_DOMAIN=myteam.cloudflareaccess.com`
   - `CF_ACCESS_AUD=<the Application's AUD tag>`

   Leaving these two unset keeps the panel's own login (see below) as the
   only gate — this layer is additive on top of it, not a replacement
   (backend RBAC is NOC-019).
5. Redeploy (`docker compose ... up -d`) so `cloudflared` (and, if you set
   the Access variables, the panel itself) pick up the new configuration.
6. Create the first operator account (there is no shared-token login
   anymore, NOC-018) — run inside the `admin` container:
   ```bash
   docker compose --env-file .env.prod -f compose/docker-compose.prod.yml \
     exec admin python scripts/panel_user.py create-user --username ops
   ```
   This first account defaults to role `owner` (NOC-019: owner/admin/analyst/viewer,
   each a superset of the ones below it — see `app/panel_rbac.py` for the
   full permission matrix). Once logged in, that owner manages everyone
   else from **Members** in the panel itself (NOC-020: invite, change
   role, deactivate/reactivate, revoke sessions — each change is recorded
   and shown on that same page). This CLI stays the operator-only escape
   hatch for when no owner account is reachable — `reset-password
   --username <name>` issues a one-time recovery link, and `set-role` /
   `deactivate-user` / `activate-user` / `revoke-sessions` work the same
   way from the shell.

Then just visit `https://<HP_ADMIN_HOST>` from anywhere — no SSH, no VPN, no
published port.

---

## 9. Upload PRO license

After logging into the admin panel, go to **Environment → License** and upload your `license.json` file.

---

## 10. Update

```bash
cd /opt/hp-app
git pull
docker build -t ghcr.io/0x-unkwn0wn/noctisapi-pro:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d --force-recreate
```
---

## 11. Data retention (optional)

```bash
sudo cp ops/cron/noctisapi-retention /etc/cron.d/hp-app-retention
```

Prunes old *rows* inside the live database (events, sessions, campaign
jobs — `scripts/prune_retention.py`). For pruning old *backup files*, see
step 11b below — a different retention policy for a different thing.

---

## 11b. Encrypted backups (NOC-026)

```bash
sudo cp ops/cron/noctisapi-backup /etc/cron.d/hp-app-backup
```

Daily, at 02:15 UTC: a consistent SQLite snapshot (`sqlite3 .backup` — the
WAL-safe online backup API, doesn't block or interfere with concurrent
writes from `app`/`admin`) plus an archive of `/var/lib/myapp` (license +
instance-id state), both encrypted with `HP_BACKUP_ENCRYPTION_KEY`
(generated once by `scripts/init_deployment.py`, same file-backed-secret
pattern as `HP_SEED` — see `compose/secrets/README.md`), written to
`/var/backups/noctisapi` — a **separate** path from the Docker volumes
backed up (`hp_prod_data`/`hp_prod_myapp`), so a problem with one doesn't
take out the other. Old backups are pruned both by age (`KEEP_DAYS`,
default 14) and by a hard count cap (`MAX_BACKUPS`, default 60) per
artifact type — the count cap catches a cron frequency change or a stuck
retention setting before the backup directory grows unbounded.

For real off-site separation (recommended — this only separates
backups from live data *on the same VPS*), sync `/var/backups/noctisapi`
to storage you control with your own `rsync`/`rclone`/cloud-CLI setup; the
files are already encrypted, so a remote storage provider never sees
plaintext.

**Access control**: the backup directory is `chmod 700`, each backup file
`chmod 600` — root-only by default, same as the rest of `/opt/hp-app`.

**Alarms**: `backup_sqlite.sh` runs under `set -euo pipefail` and exits
non-zero on any failure (SQLite integrity check failed, encryption
failed, etc.) — cron already emails root on a non-empty stderr by
default on most distros; add your own `MAILTO=` to the cron file, or
check `/var/log/noctisapi-backup.log` / wire the cron job's exit code
into whatever ops monitoring you already run, the same pattern
`scripts/verify_domain.py` (NOC-024) uses.

**Restoring**:

```bash
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml down
./restore_backup.sh db    /var/backups/noctisapi/<timestamp>-honeypot.db.enc
./restore_backup.sh myapp /var/backups/noctisapi/<timestamp>-myapp.tar.enc
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

Asks for a typed `yes` confirmation before overwriting the live volume —
there's no undo once you confirm.

---

## 12. systemd auto-start (optional)

```bash
sudo cp ops/vps/hp-app.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hp-app.service
```

---

## 13. Managed variant (NOC-023/NOC-025)

This whole document describes the **self-hosted** path — a customer
clones the repo and runs `docker-compose.prod.yml` themselves. That path
is unchanged and keeps working on its own (ADR 0001).

**Managed** is for an operator-provisioned instance: the same
`docker-compose.prod.yml`, plus an override layer
(`compose/docker-compose.managed.yml`) that adds two things steps 1–12
don't need:

1. A **pinned, non-`latest` image version** — `MANAGED_APP_VERSION` has no
   default. Leaving it unset breaks the image reference loudly at `pull`/`up`
   time rather than silently floating to whichever `:latest` happens to exist.
2. **`HP_SEED` as a Docker secret** (file-backed) instead of a plain env
   var — the one value this product explicitly never rotates (see §3's
   table), so it's the one most worth keeping out of `docker
   inspect`/`/proc/.../environ`.

Everything else — networks, healthchecks, volumes, container hardening,
Traefik/Cloudflare config, the admin console itself — comes from
`docker-compose.prod.yml` unchanged; the override doesn't duplicate it.

```bash
python scripts/init_deployment.py --public-host <HP_PUBLIC_HOST> --admin-host <HP_ADMIN_HOST>
# generates compose/secrets/hp_seed.txt (once, never overwritten on a
# later run) and compose/secrets/deployment-manifest.json -- see
# compose/secrets/README.md for what's secret and what isn't, and the
# rotation procedure for each.

# .env.prod as in step 3, plus:
echo "MANAGED_APP_VERSION=1.4.2" >> .env.prod   # an exact tag, never "latest"

make managed-pull
make managed-up
```

Re-run `scripts/init_deployment.py` after every upgrade/redeploy — it's
idempotent (step 4 of `test_init_deployment.py` covers this directly):
the seed and `deployment_id` are left untouched, only the manifest's host
fields and `updated_at` refresh.

(`make managed-*` targets layer both compose files with one `--env-file
.env.prod`, same as `make prod-*` does for the self-hosted path.)

**Rollback**: a Managed instance's only moving part on top of self-hosted
is the pinned version, so rolling back is pointing `MANAGED_APP_VERSION`
at the previous known-good tag and recreating:

```bash
sed -i 's/^MANAGED_APP_VERSION=.*/MANAGED_APP_VERSION=<previous-tag>/' .env.prod
make managed-pull
make managed-up   # recreates app/admin/migrate on the previous image; data volumes are untouched
```

This is a manual procedure for now — automated, verified upgrade/rollback
with pre-flight checks is NOC-029's job, built on this same version-pin
mechanism.

---

**Migration fails:**

```bash
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml down
docker logs compose-migrate-1
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

**Admin panel unreachable at `https://<HP_ADMIN_HOST>`:**
Check `docker logs compose-cloudflared-1` — almost always a missing or
invalid `CLOUDFLARE_TUNNEL_TOKEN`, or the Public Hostname in the Cloudflare
dashboard not pointing at `admin:9001`.

**Admin panel redirects to `/login` and no credentials work (NOC-018):**
There is no shared-token login anymore. Create (or recover) an account with
`scripts/panel_user.py` — see step 8.6 above.

**Admin panel logs in fine but specific actions return `403 Forbidden` (NOC-019):**
That account's role doesn't meet the minimum required for that action —
check `scripts/panel_user.py list-users` and the matrix in `app/panel_rbac.py`.
Promote with `scripts/panel_user.py set-role --username <name> --role <role>`.

**Admin panel returns `401 Unauthorized` on every request (NOC-017):**
`CF_ACCESS_TEAM_DOMAIN`/`CF_ACCESS_AUD` are set but don't match the Access
Application actually in front of your Public Hostname — double check the
Application's AUD tag in the Cloudflare dashboard against `.env.prod`. If
you don't want this layer yet, unset both variables and redeploy.

**Admin panel shows old UI after update:**
```bash
docker build -t ghcr.io/0x-unkwn0wn/noctisapi-pro:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d --force-recreate
```

