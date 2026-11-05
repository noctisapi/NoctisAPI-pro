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
   full permission matrix). Pass `--role admin|analyst|viewer` for
   additional accounts, or change one later with `set-role --username
   <name> --role <role>`. Use `scripts/panel_user.py reset-password
   --username <name>` to issue a one-time recovery link for an existing
   account, and `list-users` / `deactivate-user` / `revoke-sessions` to
   manage access. There is no self-service invite UI yet — all of this is
   operator-run.

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
sudo cp ops/cron/noctisapi-core-retention /etc/cron.d/hp-app-retention
```

---

## 12. systemd auto-start (optional)

```bash
sudo cp ops/vps/hp-app.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hp-app.service
```

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

