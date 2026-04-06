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
# Port 9001 (admin panel) stays 127.0.0.1-only — access via SSH tunnel only
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

The admin panel runs on port 9001 **bound to localhost only** (`127.0.0.1:9001`).
Access it via SSH tunnel from your local machine:

```bash
# On your local machine:
ssh -L 9001:127.0.0.1:9001 user@your-server-ip
# Then open http://localhost:9001
```

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

**Port 9001 already allocated:**
An old container is still running. Run `docker compose ... down` first.

**Admin panel shows old UI after update:**
```bash
docker build -t ghcr.io/0x-unkwn0wn/noctisapi-pro:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d --force-recreate
```

