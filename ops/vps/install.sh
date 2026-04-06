#!/usr/bin/env bash
# NoctisAPI PRO — self-contained installer (R2 distribution)
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   bash install.sh --download-url "PRESIGNED_R2_URL"
#
# Or via env var:
#   DOWNLOAD_URL="PRESIGNED_R2_URL" bash install.sh
#
# What it does:
#   1. Downloads the Docker image tarball from the presigned R2 URL
#   2. Loads it with docker load
#   3. Prompts for required values and writes .env.prod (skipped if exists)
#   4. Writes docker-compose.prod.yml (skipped if exists)
#   5. Starts the stack with docker compose up -d
#
# Re-running is safe: existing .env.prod and compose file are never overwritten.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${INSTALL_DIR}/.env.prod"
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.prod.yml"

# ── parse args ────────────────────────────────────────────────────────────────
DOWNLOAD_URL="${DOWNLOAD_URL:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --download-url) DOWNLOAD_URL="$2"; shift 2 ;;
    --install-dir)  INSTALL_DIR="$2";  shift 2 ;;
    --help|-h)
      echo "Usage: bash install.sh --download-url PRESIGNED_URL [--install-dir DIR]"
      exit 0 ;;
    *) echo "  Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── helpers ───────────────────────────────────────────────────────────────────
_ask() {
  local prompt="$1" default="${2:-}" answer
  if [[ -n "${default}" ]]; then
    read -r -p "  ${prompt} [${default}]: " answer
    echo "${answer:-${default}}"
  else
    while true; do
      read -r -p "  ${prompt}: " answer
      [[ -n "${answer}" ]] && { echo "${answer}"; return; }
      echo "    (required)" >&2
    done
  fi
}

_ask_optional() {
  local prompt="$1" answer
  read -r -p "  ${prompt} [blank to skip]: " answer
  echo "${answer:-}"
}

# ── banner ────────────────────────────────────────────────────────────────────
echo ""
echo "  NoctisAPI PRO — Installation Wizard"
echo "  ════════════════════════════════════"
echo ""

# ── prereqs ───────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "  ERROR: docker is not installed." >&2; exit 1; }
docker compose version >/dev/null 2>&1 \
  || { echo "  ERROR: docker compose plugin not found (requires Docker 20.10+)." >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "  ERROR: curl is not installed." >&2; exit 1; }

# ── step 1: download and load Docker image ────────────────────────────────────
echo "  Step 1/3 — Docker Image"
echo "  ─────────────────────────"

if [[ -z "${DOWNLOAD_URL}" ]]; then
  echo "  No --download-url provided."
  echo "  If you already have the image loaded, press Enter to skip download."
  read -r -p "  Paste presigned download URL (blank to skip): " DOWNLOAD_URL
fi

HP_IMAGE="noctisapi-pro"
APP_VERSION="latest"

if [[ -n "${DOWNLOAD_URL}" ]]; then
  TMP_TAR="$(mktemp /tmp/noctisapi-pro-XXXXXX.tar)"
  # shellcheck disable=SC2064
  trap 'rm -f "${TMP_TAR}"' EXIT

  echo "  Downloading image tarball…"
  if ! curl -fL --retry 3 --retry-delay 5 --progress-bar \
       -o "${TMP_TAR}" "${DOWNLOAD_URL}"; then
    echo "" >&2
    echo "  ERROR: download failed. The presigned URL may have expired." >&2
    echo "  Request a new URL from your NoctisAPI PRO dashboard." >&2
    exit 1
  fi

  echo "  Loading image into Docker…"
  LOAD_OUTPUT="$(docker load < "${TMP_TAR}" 2>&1)"
  echo "  ${LOAD_OUTPUT}"

  # Extract tag: "Loaded image: noctisapi-pro:1.2.3"
  LOADED_REF="$(echo "${LOAD_OUTPUT}" | grep -oE '[^[:space:]]+:[^[:space:]]+$' | head -1 || true)"
  if [[ -n "${LOADED_REF}" ]]; then
    HP_IMAGE="${LOADED_REF%%:*}"
    APP_VERSION="${LOADED_REF##*:}"
    echo "  Image ready: ${LOADED_REF}"
  else
    echo "  WARNING: could not parse image tag from docker load output." >&2
    echo "  Set HP_IMAGE and APP_VERSION in .env.prod manually." >&2
  fi

  rm -f "${TMP_TAR}"
  trap - EXIT
else
  echo "  Skipping download — using existing Docker image."
  # Try to detect an existing noctisapi-pro image
  EXISTING="$(docker images --format '{{.Repository}}:{{.Tag}}' \
    | grep -E '^noctisapi-pro:' | head -1 || true)"
  if [[ -n "${EXISTING}" ]]; then
    HP_IMAGE="${EXISTING%%:*}"
    APP_VERSION="${EXISTING##*:}"
    echo "  Found existing image: ${EXISTING}"
  fi
fi

# ── step 2: .env.prod ─────────────────────────────────────────────────────────
if [[ -f "${ENV_FILE}" ]]; then
  echo ""
  echo "  .env.prod already exists — skipping wizard."
  echo "  Delete ${ENV_FILE} and re-run to reconfigure."
  # Update image vars in existing env file if we loaded a new image
  if [[ -n "${HP_IMAGE}" && "${HP_IMAGE}" != "noctisapi-pro" ]]; then
    sed -i "s|^HP_IMAGE=.*|HP_IMAGE=${HP_IMAGE}|" "${ENV_FILE}" || true
    sed -i "s|^APP_VERSION=.*|APP_VERSION=${APP_VERSION}|" "${ENV_FILE}" || true
    echo "  Updated HP_IMAGE=${HP_IMAGE} APP_VERSION=${APP_VERSION} in .env.prod"
  fi
else
  echo ""
  echo "  Step 2/3 — Configuration"
  echo "  ─────────────────────────"
  HP_PUBLIC_HOST=$(_ask "Public API domain" "")
  HP_ADMIN_HOST=$(_ask  "Admin panel domain" "admin.${HP_PUBLIC_HOST}")
  ACME_EMAIL=$(_ask     "Let's Encrypt email" "")
  HP_DEPLOYMENT_ID=$(_ask "Deployment label" "prod-001")

  HP_SEED="$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
           || openssl rand -hex 32)"
  echo "  HP_SEED: auto-generated."

  echo ""
  echo "  Writing ${ENV_FILE}..."
  cat > "${ENV_FILE}" <<ENVEOF
# NoctisAPI PRO — generated by install.sh
APP_ENV=prod
APP_VERSION=${APP_VERSION}
HP_IMAGE=${HP_IMAGE}
DATABASE_URL=sqlite+pysqlite:////data/honeypot.db
HP_ASN_RESOLVER_URL=https://ipwho.is/{ip}
HP_PUBLIC_HOST=${HP_PUBLIC_HOST}
HP_ADMIN_HOST=${HP_ADMIN_HOST}
ACME_EMAIL=${ACME_EMAIL}
HP_SEED=${HP_SEED}
HP_ENFORCE_LICENSE=1
HP_DEPLOYMENT_ID=${HP_DEPLOYMENT_ID}
LOG_LEVEL=info
ENVEOF

  chmod 600 "${ENV_FILE}"
  echo "  .env.prod written (mode 600)."
fi

# ── step 3: docker-compose.prod.yml ──────────────────────────────────────────
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo ""
  echo "  docker-compose.prod.yml already exists — skipping."
else
  echo ""
  echo "  Step 3/3 — Compose file"
  echo "  ─────────────────────────"
  mkdir -p "${INSTALL_DIR}/data/siem"
  cat > "${COMPOSE_FILE}" <<'COMPOSEEOF'
services:
  migrate:
    image: ${HP_IMAGE}:${APP_VERSION}
    user: "0:0"
    command: ["sh", "-c", "chown -R 10001:0 /data /var/lib/myapp && alembic upgrade head"]
    env_file:
      - .env.prod
    volumes:
      - hp_prod_data:/data
      - hp_prod_myapp:/var/lib/myapp
    restart: "no"

  app:
    image: ${HP_IMAGE}:${APP_VERSION}
    user: "10001:0"
    env_file:
      - .env.prod
    environment:
      - PYTHONPATH=/app
    command: ["python", "main.py"]
    volumes:
      - hp_prod_data:/data
      - hp_prod_myapp:/var/lib/myapp
      - /etc/machine-id:/etc/host-machine-id:ro
      - ./data/siem:/var/log/noctisapi
    expose:
      - "8000"
    depends_on:
      migrate:
        condition: service_completed_successfully
    healthcheck:
      test: ["CMD", "python", "scripts/check_app_ready.py"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.hp-api.rule=Host(`${HP_PUBLIC_HOST}`)"
      - "traefik.http.routers.hp-api.entrypoints=websecure"
      - "traefik.http.routers.hp-api.tls.certresolver=letsencrypt"
      - "traefik.http.services.hp-api.loadbalancer.server.port=8000"
      - "traefik.http.routers.hp-api.middlewares=hp-public-ratelimit"
      - "traefik.http.middlewares.hp-public-ratelimit.ratelimit.average=${HP_PUBLIC_RATELIMIT_AVG:-120}"
      - "traefik.http.middlewares.hp-public-ratelimit.ratelimit.burst=${HP_PUBLIC_RATELIMIT_BURST:-240}"
      - "traefik.http.routers.hp-health.rule=Host(`${HP_PUBLIC_HOST}`) && (Path(`/health`) || Path(`/status`))"
      - "traefik.http.routers.hp-health.entrypoints=websecure"
      - "traefik.http.routers.hp-health.tls.certresolver=letsencrypt"
      - "traefik.http.routers.hp-health.service=hp-api"
      - "traefik.http.routers.hp-health.priority=100"
      - "traefik.http.routers.hp-health.middlewares=hp-monitor-headers,hp-monitor-ratelimit"
      - "traefik.http.middlewares.hp-monitor-headers.headers.customrequestheaders.X-Internal-Monitor=1"
      - "traefik.http.middlewares.hp-monitor-ratelimit.ratelimit.average=30"
      - "traefik.http.middlewares.hp-monitor-ratelimit.ratelimit.burst=60"
      - "traefik.http.routers.hp-internal.rule=PathPrefix(`/`)"
      - "traefik.http.routers.hp-internal.entrypoints=webinternal"
      - "traefik.http.routers.hp-internal.service=hp-api"
      - "traefik.http.routers.hp-internal.priority=120"
      - "traefik.http.routers.hp-internal.middlewares=hp-monitor-headers,hp-monitor-ratelimit"

  admin:
    image: ${HP_IMAGE}:${APP_VERSION}
    user: "10001:0"
    env_file:
      - .env.prod
    environment:
      - PYTHONPATH=/app
      - HONEYPOT_MONITOR_BASE_URL=http://app:8000
    command: ["python", "main_panel.py"]
    volumes:
      - hp_prod_data:/data
      - hp_prod_myapp:/var/lib/myapp
      - /etc/machine-id:/etc/host-machine-id:ro
    expose:
      - "9001"
    ports:
      - "127.0.0.1:9001:9001"
    depends_on:
      migrate:
        condition: service_completed_successfully
    restart: unless-stopped

  traefik:
    image: traefik:v2.11
    restart: unless-stopped
    command:
      - "--api.dashboard=false"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.webinternal.address=:8081"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=${ACME_EMAIL}"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:8081:8081"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik_letsencrypt:/letsencrypt
    depends_on:
      app:
        condition: service_healthy
      admin:
        condition: service_started

volumes:
  hp_prod_data:
  hp_prod_myapp:
  traefik_letsencrypt:
COMPOSEEOF
  echo "  docker-compose.prod.yml written."
fi

# ── start ─────────────────────────────────────────────────────────────────────
echo ""
echo "  Starting services…"
docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d --remove-orphans
docker image prune -f >/dev/null 2>&1 || true

# ── done ─────────────────────────────────────────────────────────────────────
echo ""
echo "  Done."
echo ""
HP_HOST_DISPLAY="$(grep -E '^HP_PUBLIC_HOST=' "${ENV_FILE}" \
  | head -1 | cut -d= -f2- | tr -d '\r' || echo '?')"
echo "  Honeypot API  : https://${HP_HOST_DISPLAY}"
echo "  Admin panel   : http://localhost:9001/dashboard  (SSH tunnel: ssh -L 9001:localhost:9001 user@${HP_HOST_DISPLAY})"
echo ""
echo "  NEXT STEPS:"
echo "  1. Check your email — your license.json was sent after purchase."
echo "     (First time? Visit https://noctisapi.com to get a license.)"
echo ""
echo "  2. Install your license (choose one):"
echo "     a) Admin panel → Settings → License → Upload license.json"
echo "     b) docker cp license.json \$(docker compose ps -q app):/var/lib/myapp/license.json"
echo "        docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} restart app admin"
echo ""
echo "  3. Verify PRO is active: http://localhost:9001  (SSH tunnel required)"
echo "     ssh -L 9001:localhost:9001 user@${HP_HOST_DISPLAY}"
echo ""
echo "  RENEWAL (annual/monthly subscriptions):"
echo "  When your subscription renews you'll receive a new license.json by email."
echo "  Replace it at /var/lib/myapp/license.json and restart:"
echo "    docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} restart app admin"
echo ""
