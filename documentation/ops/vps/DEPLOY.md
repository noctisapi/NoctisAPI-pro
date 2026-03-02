# NoctisAPI VPS Deployment (Ubuntu 22.04+)

This is a concrete, repeatable deployment flow for a single VPS with Docker + Traefik (ACME).

## 1. System Prep

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release ufw
```

Install Docker + Compose plugin:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Firewall (open only SSH + web):

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

## 2. App Layout

```bash
sudo mkdir -p /opt/hp-app
sudo chown -R $USER:$USER /opt/hp-app
cd /opt/hp-app
```

Copy the repo here (git clone or rsync).

## 3. Production Env

Edit `.env.prod` and set:

- `APP_VERSION` to the pushed image tag (e.g., `latest`).
- `HP_PUBLIC_BASE_URL=https://<your-api-host>`
- `HP_PUBLIC_HOST=<api-host>`
- `HP_ADMIN_HOST=<admin-host>`
- `ACME_EMAIL=<you@example.com>`
- `HP_SEED` to a long random secret.
- `HP_GEOIP_DB=/app/data/GeoLite2-Country.mmdb` (keep default unless you move it).
- Optional campaign tuning:
  - `HP_CAMPAIGN_AUTO_RECOMPUTE_THRESHOLD` (>0 to enable)
  - `HP_CAMPAIGN_AUTO_RECOMPUTE_INTERVAL` (seconds)

## 4. TLS (Traefik + ACME)

Traefik handles certificates automatically via ACME HTTP-01.
Ensure:
- Ports 80/443 are open
- `ACME_EMAIL` is set in `.env.prod`
Once Traefik starts, it will request certs automatically.

## 5. Launch

```bash
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod pull
docker compose -f compose/docker-compose.prod.yml --env-file .env.prod up -d
```

Verify:

```bash
curl -sS https://<your-api-host>/health
```

The admin panel is exposed via Traefik on `HP_ADMIN_HOST`.

## 6. systemd (optional)

Enable auto-start with the unit file in `ops/vps/hp-app.service`:

```bash
sudo cp ops/vps/hp-app.service /etc/systemd/system/hp-app.service
sudo systemctl daemon-reload
sudo systemctl enable --now hp-app.service
sudo systemctl status hp-app.service
```

## 7. Backups

Configure the cron from `ops/cron/yourapp-backup` and point it to:

- `BACKUP_DIR=/var/backups/honey-app`
- `DATA_VOLUME=hp_prod_data`
- `APP_DB_PATH=/data/honeypot.db`
