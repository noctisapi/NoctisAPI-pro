#!/usr/bin/env bash
# upgrade.sh — Upgrade NoctisAPI Core → Pro
#
# Usage:
#   bash upgrade.sh --license-key sk_live_XXXX [options]
#
# Options:
#   --license-key KEY     PRO license key (required)
#   --license-file PATH   Offline license.json to install for runtime validation (optional)
#   --dir PATH            Installation directory (default: current directory)
#   --yes                 Skip confirmation prompts
#
# What it does:
#   1. Validates the license key and fetches a presigned download URL from R2
#   2. Downloads the PRO Docker image tar and loads it
#   3. Updates .env with PRO image reference and licensing vars
#   4. Installs license.json into the data volume (if --license-file provided)
#   5. Restarts services with the new image (preserving all data)
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
LICENSING_SERVER="${LICENSING_SERVER:-https://license.unkwn0wn.com}"
LICENSE_KEY=""
LICENSE_FILE=""
INSTALL_DIR="$(pwd)"
LOCAL_IMAGE="noctisapi-pro"   # stable local tag — no external registry dependency
AUTO_YES=0

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
BOLD="\033[1m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; RESET="\033[0m"
info()    { echo -e "${GREEN}==>${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}[$1]${RESET} $2"; }
prompt()  { echo -e "${BOLD}$*${RESET}"; }

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --license-key)  LICENSE_KEY="$2";       shift 2 ;;
    --license-file) LICENSE_FILE="$2";      shift 2 ;;
    --server)       LICENSING_SERVER="$2";  shift 2 ;;
    --dir)          INSTALL_DIR="$2";       shift 2 ;;
    --yes)          AUTO_YES=1;             shift   ;;
    *) error "Unknown option: $1" ;;
  esac
done

[[ -z "$LICENSE_KEY" ]]       && error "--license-key is required."
[[ ! -d "$INSTALL_DIR" ]]     && error "Install directory not found: $INSTALL_DIR"

ENV_FILE="${INSTALL_DIR}/.env"
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
step "0/5" "Checking dependencies"
for cmd in curl docker jq; do
  command -v "$cmd" &>/dev/null || error "'$cmd' is required but not installed."
done
docker compose version &>/dev/null || error "docker compose (v2) is required."
info "All dependencies OK"

# ---------------------------------------------------------------------------
# Detect existing installation
# ---------------------------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  warn "No .env found in ${INSTALL_DIR}. This looks like a fresh setup, not an upgrade."
  warn "If you want a fresh install, use install.sh instead."
  [[ "$AUTO_YES" -eq 0 ]] && { prompt "Continue anyway? [y/N]"; read -r yn; [[ "$yn" =~ ^[Yy]$ ]] || exit 0; }
fi

# ---------------------------------------------------------------------------
# Step 1 — Validate license and get download URL
# ---------------------------------------------------------------------------
step "1/5" "Validating license key"

HTTP_CODE=$(curl --silent --output /tmp/_noctis_resp.json --write-out "%{http_code}" \
  -X POST "${LICENSING_SERVER}/v1/distribution/download" \
  -H "X-License-Key: ${LICENSE_KEY}")

if [[ "$HTTP_CODE" != "200" ]]; then
  DETAIL=$(jq -r '.detail // "unknown error"' /tmp/_noctis_resp.json 2>/dev/null || echo "unknown")
  case "$HTTP_CODE" in
    401) error "Invalid or expired license key." ;;
    403) error "License rejected: ${DETAIL}" ;;
    404) error "PRO image not available yet. Contact support." ;;
    501) error "Distribution not configured on server. Contact support." ;;
    *)   error "Unexpected error (HTTP ${HTTP_CODE}): ${DETAIL}" ;;
  esac
fi

DOWNLOAD_URL=$(jq -r '.download_url'   /tmp/_noctis_resp.json)
FILENAME=$(jq -r '.filename'           /tmp/_noctis_resp.json)
VERSION=$(jq -r '.image_version'       /tmp/_noctis_resp.json)
EXPECTED_SHA256=$(jq -r '.sha256 // empty' /tmp/_noctis_resp.json 2>/dev/null || true)
rm -f /tmp/_noctis_resp.json

info "License valid — PRO image version: ${BOLD}${VERSION}${RESET}"

# ---------------------------------------------------------------------------
# Confirm upgrade
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo -e "${BOLD}  NoctisAPI Core → Pro Upgrade${RESET}"
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo -e "  Install dir : ${INSTALL_DIR}"
echo -e "  PRO version : ${VERSION}"
echo -e "  Image       : ${LOCAL_IMAGE}:${VERSION} (local)"
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo ""
if [[ "$AUTO_YES" -eq 0 ]]; then
  prompt "Proceed with upgrade? [y/N]"
  read -r yn
  [[ "$yn" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# ---------------------------------------------------------------------------
# Step 2 — Download and load PRO image
# ---------------------------------------------------------------------------
step "2/5" "Downloading PRO image"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${FILENAME}..."
curl --progress-bar --location -o "${TMP_DIR}/${FILENAME}" "$DOWNLOAD_URL"

# Verify SHA256 checksum if the server provided one
if [[ -n "${EXPECTED_SHA256:-}" ]]; then
  info "Verifying SHA256 checksum..."
  if command -v sha256sum &>/dev/null; then
    ACTUAL_SHA256=$(sha256sum "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
  elif command -v shasum &>/dev/null; then
    ACTUAL_SHA256=$(shasum -a 256 "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
  else
    warn "sha256sum / shasum not available — skipping verification"
    ACTUAL_SHA256=""
  fi
  if [[ -n "$ACTUAL_SHA256" ]]; then
    if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
      error "SHA256 mismatch!\n  Expected : ${EXPECTED_SHA256}\n  Actual   : ${ACTUAL_SHA256}\nThe download may be corrupted or tampered with."
    fi
    info "Checksum verified: ${ACTUAL_SHA256}"
  fi
else
  warn "Server did not provide a SHA256 checksum — skipping integrity check."
fi

info "Loading Docker image..."
LOAD_OUTPUT=$(docker load -i "${TMP_DIR}/${FILENAME}")
LOADED_REF=$(echo "$LOAD_OUTPUT" | grep "^Loaded image:" | grep -v "^Loaded image ID:" | awk '{print $NF}' || true)
if [[ -z "$LOADED_REF" ]]; then
  LOADED_REF=$(echo "$LOAD_OUTPUT" | grep "^Loaded image ID:" | awk '{print $NF}' || true)
fi
[[ -z "$LOADED_REF" ]] && error "Could not determine loaded image ref:\n${LOAD_OUTPUT}"

info "Retagging to local stable name: ${LOCAL_IMAGE}:${VERSION} / ${LOCAL_IMAGE}:latest"
docker tag "$LOADED_REF" "${LOCAL_IMAGE}:${VERSION}"
docker tag "$LOADED_REF" "${LOCAL_IMAGE}:latest"
if [[ "$LOADED_REF" != sha256:* ]]; then
  docker rmi "$LOADED_REF" 2>/dev/null || true
fi
info "Image loaded: ${LOCAL_IMAGE}:${VERSION}"

# ---------------------------------------------------------------------------
# Step 3 — Update .env
# ---------------------------------------------------------------------------
step "3/5" "Updating .env"

_env_set() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
    info "  Updated ${key}"
  else
    echo "${key}=${val}" >> "$ENV_FILE"
    info "  Added   ${key}"
  fi
}

# Create .env if it doesn't exist
touch "$ENV_FILE"

_env_set "HP_IMAGE"    "${LOCAL_IMAGE}"
_env_set "APP_VERSION" "${VERSION}"

# GeoIP: Pro stores it in the data volume at /data/ (not a bind-mount like Core)
_env_set "HP_GEOIP_DB" "/data/GeoLite2-Country.mmdb"

# PRO licensing vars
_env_set "HP_LICENSE_MODE"                      "offline"
_env_set "HP_ENFORCE_LICENSE"                   "1"
_env_set "HP_LICENSE_STATUS_REFRESH_SECONDS"    "30"
_env_set "HP_LICENSE_STATUS_MAX_REFRESH_SECONDS" "300"
_env_set "INSTANCE_ID_PATH"                     "/var/lib/myapp/instance_id"
_env_set "HP_OFFLINE_LICENSE_PATH"              "/var/lib/myapp/license.json"
_env_set "HP_OFFLINE_LICENSE_STATE_PATH"        "/var/lib/myapp/license_state.json"
_env_set "HP_OFFLINE_PUBLIC_KEYS_BUNDLE_PATH"   "/app/app/offline_public_keys.json"

info ".env updated"

# Preserve old compose project name so existing volumes survive
OLD_PROJECT=$(cd "$INSTALL_DIR" && docker compose config --format json 2>/dev/null \
  | jq -r '.name // ""' 2>/dev/null || echo "")
if [[ -n "$OLD_PROJECT" ]]; then
  _env_set "COMPOSE_PROJECT_NAME" "$OLD_PROJECT"
  COMPOSE_PROJECT="$OLD_PROJECT"
else
  COMPOSE_PROJECT=$(basename "$INSTALL_DIR")
fi

ENV_BASENAME=$(basename "$ENV_FILE")

# ---------------------------------------------------------------------------
# Step 3b — Write Pro docker-compose.yml (replaces Core compose)
# ---------------------------------------------------------------------------
step "3b/5" "Writing Pro docker-compose.yml"

[[ -f "$COMPOSE_FILE" ]] && cp "$COMPOSE_FILE" "${COMPOSE_FILE}.core-backup" && info "Backed up existing compose to docker-compose.yml.core-backup"
mkdir -p "${INSTALL_DIR}/data/siem"

cat > "$COMPOSE_FILE" <<'COMPOSE_EOF'
# NoctisAPI PRO — written by upgrade.sh
# Images are loaded locally from tar; pull_policy: never prevents any registry pull.
services:
  migrate:
    image: ${HP_IMAGE:-noctisapi-pro}:${APP_VERSION:-latest}
    pull_policy: never
    user: "0:0"
    command: ["sh", "-c", "chown -R 10001:0 /data /var/lib/myapp && alembic upgrade head && python scripts/download_geoip.py"]
    env_file:
      - ENVFILE_PLACEHOLDER
    volumes:
      - hp_prod_data:/data
      - hp_prod_myapp:/var/lib/myapp
    restart: "no"

  app:
    image: ${HP_IMAGE:-noctisapi-pro}:${APP_VERSION:-latest}
    pull_policy: never
    user: "10001:0"
    read_only: true
    tmpfs:
      - /tmp:size=64m,noexec,nosuid
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    env_file:
      - ENVFILE_PLACEHOLDER
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
    image: ${HP_IMAGE:-noctisapi-pro}:${APP_VERSION:-latest}
    pull_policy: never
    user: "10001:0"
    read_only: true
    tmpfs:
      - /tmp:size=32m,noexec,nosuid
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    env_file:
      - ENVFILE_PLACEHOLDER
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
COMPOSE_EOF

sed -i "s|ENVFILE_PLACEHOLDER|${ENV_BASENAME}|g" "$COMPOSE_FILE"
info "docker-compose.yml written"

# ---------------------------------------------------------------------------
# Step 4 — Install license.json into volume
# ---------------------------------------------------------------------------
step "4/5" "Installing license.json"

LIC_TMP="${TMP_DIR}/license.json"

if [[ -n "$LICENSE_FILE" ]]; then
  [[ ! -f "$LICENSE_FILE" ]] && error "License file not found: ${LICENSE_FILE}"
  jq empty "$LICENSE_FILE" 2>/dev/null || error "Invalid JSON in license file: ${LICENSE_FILE}"
  cp "$LICENSE_FILE" "$LIC_TMP"
  info "Using provided license file"
else
  info "Fetching license.json from license server..."
  HTTP_CODE=$(curl --silent --output "$LIC_TMP" --write-out "%{http_code}" \
    -H "X-License-Key: ${LICENSE_KEY}" \
    "${LICENSING_SERVER}/v1/distribution/license-file")
  if [[ "$HTTP_CODE" != "200" ]]; then
    DETAIL=$(jq -r '.detail // "unknown"' "$LIC_TMP" 2>/dev/null || echo "unknown")
    case "$HTTP_CODE" in
      404) error "No license.json issued yet. Contact support." ;;
      *)   error "Could not fetch license.json (HTTP $HTTP_CODE): $DETAIL" ;;
    esac
  fi
  jq empty "$LIC_TMP" 2>/dev/null || error "Invalid license.json received from server."
  info "license.json fetched from server"
fi

VOLUME_NAME="${COMPOSE_PROJECT}_hp_prod_myapp"
docker volume create "$VOLUME_NAME" &>/dev/null || true
info "Installing into volume ${VOLUME_NAME}..."
docker run --rm \
  -v "${VOLUME_NAME}:/var/lib/myapp" \
  -v "${LIC_TMP}:/tmp/license.json:ro" \
  busybox sh -c \
    "mkdir -p /var/lib/myapp && \
     cp /tmp/license.json /var/lib/myapp/license.json && \
     chown 10001:0 /var/lib/myapp/license.json && \
     chmod 600 /var/lib/myapp/license.json"
info "license.json installed"

# ---------------------------------------------------------------------------
# Step 5 — Restart services (no pull — images are already local)
# ---------------------------------------------------------------------------
step "5/5" "Restarting services"

cd "$INSTALL_DIR"
info "Restarting with PRO image (local, no pull)..."
docker compose up -d --remove-orphans

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}✔ Upgrade to NoctisAPI Pro ${VERSION} complete!${RESET}"
echo ""
echo -e "  Logs:   ${CYAN}docker compose logs -f app${RESET}"
echo -e "  Stop:   ${CYAN}cd ${INSTALL_DIR} && docker compose down${RESET}"
echo ""
