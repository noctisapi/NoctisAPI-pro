# Production Runbook

This runbook covers:
- Initial VPS setup
- DuckDNS configuration
- Production deploy with Traefik + ACME
- Making the deployment repeatable on new machines

## Prerequisites
- VPS with public IP and SSH access
- DuckDNS subdomain + token
- Docker image published (e.g. `ghcr.io/<ORG>/hp-app`)
- `.env.prod` prepared with real values (kept on the server, not inside the image)

## Phase 1: VPS Baseline
1. Update packages:
   - `sudo apt update && sudo apt -y upgrade`
2. Install Docker + Compose plugin:
   - `sudo apt -y install docker.io docker-compose-plugin`
3. Add your user to docker group:
   - `sudo usermod -aG docker $USER`
   - Reconnect your SSH session.
4. Open firewall:
   - `sudo ufw allow 22`
   - `sudo ufw allow 80`
   - `sudo ufw allow 443`
   - `sudo ufw enable`

## Phase 2: DuckDNS
1. Create update script:
   - `mkdir -p ~/duckdns`
   - `cat > ~/duckdns/duck.sh <<'SH'`
     - `#!/usr/bin/env bash`
     - `echo url="https://www.duckdns.org/update?domains=<SUBDOMAIN>&token=<TOKEN>&ip=" | curl -k -o ~/duckdns/duck.log -K -`
     - `SH`
   - `chmod +x ~/duckdns/duck.sh`
2. Cron every 5 min:
   - `crontab -e`
   - add: `*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1`
3. Verify:
   - `nslookup <SUBDOMAIN>.duckdns.org` should resolve to VPS IP.

## Phase 3: Repo Layout on VPS
1. Create deployment directory:
   - `mkdir -p /opt/hp-app`
2. Clone repo:
   - `git clone <REPO_URL> /opt/hp-app`
3. Create `.env.prod` (not baked into the image):
   - `cp /opt/hp-app/.env.prod /opt/hp-app/.env.prod`
   - Fill real values (tokens, URLs, passwords).
   - Add:
     - `HP_IMAGE=ghcr.io/<ORG>/hp-app`
     - `HP_PUBLIC_HOST=<SUBDOMAIN>.duckdns.org`
     - `ACME_EMAIL=<you@example.com>`
     - `HONEYPOT_PUBLIC_BASE_URL=https://<SUBDOMAIN>.duckdns.org` (public URL shown in admin)
     - `HONEYPOT_MONITOR_BASE_URL=http://traefik:8081` (internal monitor URL, no dashboard noise)
     - `HP_SEED=<long random secret>` (stable actor IDs + secrets)
     - `HP_REQUIRE_SEED=1` (optional, fail startup if HP_SEED is missing/placeholder)
     - `HP_ACTOR_UA_MODE=family` (recommended; `ip` or `full` also supported)
     - `HP_PUBLIC_RATELIMIT_AVG=120` / `HP_PUBLIC_RATELIMIT_BURST=240` (optional; Traefik rate limit)

## Phase 4: Certificates (Traefik + ACME)
Traefik handles certificates automatically via ACME HTTP-01.
1. Ensure ports 80/443 are open.
2. Set `ACME_EMAIL` in `.env.prod`.
3. First deploy will request certs automatically.

## Phase 5: First Production Deploy
1. Ensure `.env.prod` is correct.
2. Run deploy:
   - `bash /opt/hp-app/ops/vps/deploy.sh`
3. Verify:
   - `curl -i https://<SUBDOMAIN>.duckdns.org/health`
   - `curl -i https://<SUBDOMAIN>.duckdns.org/docs`
   - Admin panel is available via SSH tunnel on `127.0.0.1:9001`

## Phase 5.1: GeoIP database (flags)
MaxMind GeoLite2 is not committed to git. Download it on the server:
1. Export credentials:
   - `export MAXMIND_ACCOUNT_ID=...`
   - `export MAXMIND_LICENSE_KEY=...`
2. Run:
   - `bash /opt/hp-app/ops/geoip/update_geoip.sh`
3. Ensure `.env.prod` uses:
   - `HP_GEOIP_DB=/app/data/GeoLite2-Country.mmdb`

## Phase 6: Repeatable Deployment on New VPS
Use the same steps with these minimal inputs:
- Repo URL
- `.env.prod`
- DuckDNS token/subdomain
- Docker image registry credentials (if private)

You can automate by:
1. Copying `.env.prod` via scp.
2. Running `ops/vps/deploy.sh`.

## Optional: GitHub Actions Deploy
Use an SSH deploy action that:
- `git pull`
- `bash ops/vps/deploy.sh`

## GitHub Actions + GHCR (automatic image build)
This repo includes `.github/workflows/ghcr.yml` which:
- Builds the Docker image on every push to `main`
- Pushes it to `ghcr.io/<OWNER>/hp-app` with tags `latest` and commit SHA

Steps:
1. Push to GitHub (`main` branch).
2. GHCR will publish the image automatically.
3. On the VPS, set:
   - `HP_IMAGE=ghcr.io/<OWNER>/hp-app`
   - `APP_VERSION=latest` (or use the SHA tag)
4. Run:
   - `bash ops/vps/deploy.sh`

## Notes on Public IP Accuracy
- Ensure your proxy (Traefik) sets `X-Forwarded-For` and `X-Real-IP`.
- Uvicorn should run with `--proxy-headers` and `--forwarded-allow-ips` if you want trusted proxy headers.
- If you need hard guarantees, restrict `forwarded-allow-ips` to your proxy IP.

