#!/usr/bin/env bash
# upgrade.sh — In-place upgrade NoctisAPI Core → Pro
#
# Strategy: same Docker project name + same data volumes + --remove-orphans.
# Core containers are replaced by PRO containers in a single operation.
# No data volumes are ever deleted.
#
# Usage:
#   bash upgrade.sh --license-key sk_live_XXXX [options]
#
# Options:
#   --license-key KEY     PRO license key (required)
#   --license-file PATH   Offline license.json (optional; fetched from server if omitted)
#   --dir PATH            Installation directory (default: current directory)
#   --yes                 Skip confirmation prompts
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
LICENSING_SERVER="${LICENSING_SERVER:-https://license.unkwn0wn.com}"
LICENSE_KEY=""
LICENSE_FILE=""
INSTALL_DIR="$(pwd)"
LOCAL_IMAGE="noctisapi-pro"
AUTO_YES=0

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
BOLD="\033[1m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; RESET="\033[0m"
info()   { echo -e "${GREEN}==>${RESET} $*"; }
warn()   { echo -e "${YELLOW}[!]${RESET} $*"; }
error()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
step()   { echo -e "\n${CYAN}${BOLD}[$1]${RESET} $2"; }
prompt() { echo -e "${BOLD}$*${RESET}"; }

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

[[ -z "$LICENSE_KEY" ]]   && error "--license-key is required."
[[ ! -d "$INSTALL_DIR" ]] && error "Install directory not found: $INSTALL_DIR"

ENV_FILE="${INSTALL_DIR}/.env"
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
step "0/6" "Checking dependencies"
for cmd in curl docker jq; do
  command -v "$cmd" &>/dev/null || error "'$cmd' is required but not installed."
done
docker compose version &>/dev/null || error "docker compose (v2) is required."
info "All dependencies OK"

# ---------------------------------------------------------------------------
# Detect Core installation
# ---------------------------------------------------------------------------
step "1/6" "Detecting Core installation"

CORE_IMAGE="ghcr.io/noctisapi/noctisapi-core"

# Find the running Core app container
CORE_APP_CONTAINER=$(docker ps -q \
  --filter "ancestor=${CORE_IMAGE}" \
  --filter "label=com.docker.compose.service=app" \
  2>/dev/null | head -1 || true)

if [[ -z "$CORE_APP_CONTAINER" ]]; then
  # Fallback: any container with the Core image
  CORE_APP_CONTAINER=$(docker ps -q --filter "ancestor=${CORE_IMAGE}" 2>/dev/null | head -1 || true)
fi

if [[ -n "$CORE_APP_CONTAINER" ]]; then
  CORE_PROJECT=$(docker inspect "$CORE_APP_CONTAINER" \
    --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null || true)
  CORE_DATA_VOLUME=$(docker inspect "$CORE_APP_CONTAINER" \
    --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' \
    2>/dev/null || true)
  CORE_TRAEFIK_VOLUME=$(docker ps -q --filter "ancestor=traefik:v2.11" \
    --filter "label=com.docker.compose.project=${CORE_PROJECT}" 2>/dev/null \
    | xargs -r docker inspect \
      --format '{{range .Mounts}}{{if eq .Destination "/letsencrypt"}}{{.Name}}{{end}}{{end}}' \
    2>/dev/null | head -1 || true)
  info "Found Core project   : ${CORE_PROJECT:-unknown}"
  info "Found data volume    : ${CORE_DATA_VOLUME:-unknown}"
  info "Found traefik volume : ${CORE_TRAEFIK_VOLUME:-unknown}"
else
  warn "No running Core containers found — proceeding with defaults."
  CORE_PROJECT=""
  CORE_DATA_VOLUME=""
  CORE_TRAEFIK_VOLUME=""
fi

# Resolve final names
COMPOSE_PROJECT="${CORE_PROJECT:-$(basename "$INSTALL_DIR")}"
DATA_VOLUME="${CORE_DATA_VOLUME:-${COMPOSE_PROJECT}_hp_prod_data}"
TRAEFIK_VOLUME="${CORE_TRAEFIK_VOLUME:-${COMPOSE_PROJECT}_traefik_letsencrypt}"
MYAPP_VOLUME="${COMPOSE_PROJECT}_hp_prod_myapp"

info "Will use project     : ${COMPOSE_PROJECT}"
info "Will use data volume : ${DATA_VOLUME}"

# ---------------------------------------------------------------------------
# Validate license and get PRO download URL
# ---------------------------------------------------------------------------
step "2/6" "Validating license key"

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

DOWNLOAD_URL=$(jq -r '.download_url'          /tmp/_noctis_resp.json)
FILENAME=$(jq -r '.filename'                  /tmp/_noctis_resp.json)
VERSION=$(jq -r '.image_version'              /tmp/_noctis_resp.json)
EXPECTED_SHA256=$(jq -r '.sha256 // empty'    /tmp/_noctis_resp.json 2>/dev/null || true)
rm -f /tmp/_noctis_resp.json

info "License valid — PRO version: ${BOLD}${VERSION}${RESET}"

# ---------------------------------------------------------------------------
# Confirm
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo -e "${BOLD}  NoctisAPI Core → Pro  (in-place upgrade)${RESET}"
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo -e "  Directory    : ${INSTALL_DIR}"
echo -e "  Project name : ${COMPOSE_PROJECT}"
echo -e "  Data volume  : ${DATA_VOLUME}  ${YELLOW}(preserved)${RESET}"
echo -e "  PRO version  : ${VERSION}"
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo ""
if [[ "$AUTO_YES" -eq 0 ]]; then
  prompt "Proceed? [y/N]"
  read -r yn
  [[ "$yn" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# ---------------------------------------------------------------------------
# Step 3 — Download and load PRO image
# ---------------------------------------------------------------------------
step "3/6" "Downloading PRO image"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${FILENAME}..."
curl --progress-bar --location -o "${TMP_DIR}/${FILENAME}" "$DOWNLOAD_URL"

if [[ -n "${EXPECTED_SHA256:-}" ]]; then
  info "Verifying checksum..."
  if command -v sha256sum &>/dev/null; then
    ACTUAL_SHA256=$(sha256sum "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
  elif command -v shasum &>/dev/null; then
    ACTUAL_SHA256=$(shasum -a 256 "${TMP_DIR}/${FILENAME}" | awk '{print $1}')
  else
    warn "sha256sum not available — skipping verification"
    ACTUAL_SHA256=""
  fi
  if [[ -n "$ACTUAL_SHA256" && "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    error "SHA256 mismatch!\n  Expected : ${EXPECTED_SHA256}\n  Actual   : ${ACTUAL_SHA256}"
  fi
  [[ -n "$ACTUAL_SHA256" ]] && info "Checksum OK: ${ACTUAL_SHA256}"
else
  warn "No checksum provided — skipping integrity check."
fi

info "Loading Docker image..."
LOAD_OUTPUT=$(docker load -i "${TMP_DIR}/${FILENAME}")
LOADED_REF=$(echo "$LOAD_OUTPUT" | grep "^Loaded image:" | grep -v "^Loaded image ID:" | awk '{print $NF}' || true)
[[ -z "$LOADED_REF" ]] && LOADED_REF=$(echo "$LOAD_OUTPUT" | grep "^Loaded image ID:" | awk '{print $NF}' || true)
[[ -z "$LOADED_REF" ]] && error "Could not determine loaded image ref:\n${LOAD_OUTPUT}"

docker tag "$LOADED_REF" "${LOCAL_IMAGE}:${VERSION}"
docker tag "$LOADED_REF" "${LOCAL_IMAGE}:latest"
[[ "$LOADED_REF" != sha256:* ]] && docker rmi "$LOADED_REF" 2>/dev/null || true
info "Image ready: ${LOCAL_IMAGE}:${VERSION}"

# ---------------------------------------------------------------------------
# Step 4 — Write PRO compose + update .env
# ---------------------------------------------------------------------------
step "4/6" "Writing PRO compose and updating .env"

# .env helpers
_env_set() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
  else
    echo "${key}=${val}" >> "$ENV_FILE"
  fi
  info "  ${key}=${val}"
}

touch "$ENV_FILE"
_env_set "HP_IMAGE"                             "${LOCAL_IMAGE}"
_env_set "APP_VERSION"                          "${VERSION}"
_env_set "COMPOSE_PROJECT_NAME"                 "${COMPOSE_PROJECT}"
_env_set "HP_GEOIP_DB"                          "/data/GeoLite2-Country.mmdb"
_env_set "HP_LICENSE_MODE"                      "offline"
_env_set "HP_ENFORCE_LICENSE"                   "1"
_env_set "HP_LICENSE_STATUS_REFRESH_SECONDS"    "30"
_env_set "HP_LICENSE_STATUS_MAX_REFRESH_SECONDS" "300"
_env_set "INSTANCE_ID_PATH"                     "/var/lib/myapp/instance_id"
_env_set "HP_OFFLINE_LICENSE_PATH"              "/var/lib/myapp/license.json"
_env_set "HP_OFFLINE_LICENSE_STATE_PATH"        "/var/lib/myapp/license_state.json"
_env_set "HP_OFFLINE_PUBLIC_KEYS_BUNDLE_PATH"   "/app/app/offline_public_keys.json"

ENV_BASENAME=$(basename "$ENV_FILE")
mkdir -p "${INSTALL_DIR}/data/siem"

# Write PRO docker-compose.yml.
# Volume declarations use `external: true` + `name:` to reference the
# existing Core volumes — Docker will NOT recreate or wipe them.
cat > "$COMPOSE_FILE" << COMPOSE_EOF
# NoctisAPI PRO — written by upgrade.sh (in-place migration)
# Data volumes are referenced as external to preserve Core data.
services:
  migrate:
    image: \${HP_IMAGE:-noctisapi-pro}:\${APP_VERSION:-latest}
    pull_policy: never
    user: "0:0"
    command: ["sh", "-c", "chown -R 10001:0 /data /var/lib/myapp && alembic upgrade head && python scripts/download_geoip.py"]
    env_file:
      - ${ENV_BASENAME}
    volumes:
      - hp_data:/data
      - hp_myapp:/var/lib/myapp
    restart: "no"

  app:
    image: \${HP_IMAGE:-noctisapi-pro}:\${APP_VERSION:-latest}
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
      - ${ENV_BASENAME}
    environment:
      - PYTHONPATH=/app
    command: ["python", "main.py"]
    volumes:
      - hp_data:/data
      - hp_myapp:/var/lib/myapp
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
      - "traefik.http.routers.hp-api.rule=Host(\`\${HP_PUBLIC_HOST}\`)"
      - "traefik.http.routers.hp-api.entrypoints=websecure"
      - "traefik.http.routers.hp-api.tls.certresolver=letsencrypt"
      - "traefik.http.services.hp-api.loadbalancer.server.port=8000"
      - "traefik.http.routers.hp-api.middlewares=hp-public-ratelimit"
      - "traefik.http.middlewares.hp-public-ratelimit.ratelimit.average=\${HP_PUBLIC_RATELIMIT_AVG:-120}"
      - "traefik.http.middlewares.hp-public-ratelimit.ratelimit.burst=\${HP_PUBLIC_RATELIMIT_BURST:-240}"
      - "traefik.http.routers.hp-health.rule=Host(\`\${HP_PUBLIC_HOST}\`) && (Path(\`/health\`) || Path(\`/status\`))"
      - "traefik.http.routers.hp-health.entrypoints=websecure"
      - "traefik.http.routers.hp-health.tls.certresolver=letsencrypt"
      - "traefik.http.routers.hp-health.service=hp-api"
      - "traefik.http.routers.hp-health.priority=100"
      - "traefik.http.routers.hp-health.middlewares=hp-monitor-headers,hp-monitor-ratelimit"
      - "traefik.http.middlewares.hp-monitor-headers.headers.customrequestheaders.X-Internal-Monitor=1"
      - "traefik.http.middlewares.hp-monitor-ratelimit.ratelimit.average=30"
      - "traefik.http.middlewares.hp-monitor-ratelimit.ratelimit.burst=60"
      - "traefik.http.routers.hp-internal.rule=PathPrefix(\`/\`)"
      - "traefik.http.routers.hp-internal.entrypoints=webinternal"
      - "traefik.http.routers.hp-internal.service=hp-api"
      - "traefik.http.routers.hp-internal.priority=120"
      - "traefik.http.routers.hp-internal.middlewares=hp-monitor-headers,hp-monitor-ratelimit"

  admin:
    image: \${HP_IMAGE:-noctisapi-pro}:\${APP_VERSION:-latest}
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
      - ${ENV_BASENAME}
    environment:
      - PYTHONPATH=/app
      - HONEYPOT_MONITOR_BASE_URL=http://app:8000
    command: ["python", "main_panel.py"]
    volumes:
      - hp_data:/data
      - hp_myapp:/var/lib/myapp
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
      - "--certificatesresolvers.letsencrypt.acme.email=\${ACME_EMAIL}"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:8081:8081"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - hp_traefik:/letsencrypt
    depends_on:
      app:
        condition: service_healthy
      admin:
        condition: service_started

volumes:
  hp_data:
    external: true
    name: ${DATA_VOLUME}
  hp_myapp:
    name: ${MYAPP_VOLUME}
  hp_traefik:
    external: true
    name: ${TRAEFIK_VOLUME}
COMPOSE_EOF

info "docker-compose.yml written (data volume: ${DATA_VOLUME})"

# ---------------------------------------------------------------------------
# Step 5 — Install license.json
# ---------------------------------------------------------------------------
step "5/6" "Installing license.json"

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
  info "license.json fetched"
fi

# Ensure the myapp volume exists before writing to it
docker volume create "${MYAPP_VOLUME}" &>/dev/null || true
docker run --rm \
  -v "${MYAPP_VOLUME}:/var/lib/myapp" \
  -v "${LIC_TMP}:/tmp/license.json:ro" \
  busybox sh -c \
    "mkdir -p /var/lib/myapp && \
     cp /tmp/license.json /var/lib/myapp/license.json && \
     chown 10001:0 /var/lib/myapp/license.json && \
     chmod 600 /var/lib/myapp/license.json"
info "license.json installed into ${MYAPP_VOLUME}"

# ---------------------------------------------------------------------------
# Step 6 — In-place switch: stop Core, start PRO (same project, same volumes)
# ---------------------------------------------------------------------------
step "6/6" "Switching Core → Pro (in-place)"

cd "$INSTALL_DIR"

# Ensure the data volume exists (it should already — this is a no-op if so)
docker volume create "${DATA_VOLUME}" &>/dev/null || true

info "Bringing up PRO with --remove-orphans (Core containers will be replaced)..."
docker compose -p "${COMPOSE_PROJECT}" up -d --remove-orphans

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
echo ""
info "Waiting for app to become healthy..."
RETRIES=12
until docker compose -p "${COMPOSE_PROJECT}" ps app 2>/dev/null | grep -q "healthy"; do
  RETRIES=$((RETRIES - 1))
  [[ "$RETRIES" -le 0 ]] && {
    warn "App did not report healthy within 60s — check logs:"
    echo -e "  docker compose -p ${COMPOSE_PROJECT} logs app"
    break
  }
  sleep 5
done
[[ "$RETRIES" -gt 0 ]] && info "App is healthy"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}✔ Upgrade to NoctisAPI Pro ${VERSION} complete!${RESET}"
echo ""
echo -e "  Project : ${CYAN}${COMPOSE_PROJECT}${RESET}"
echo -e "  Logs    : ${CYAN}docker compose -p ${COMPOSE_PROJECT} logs -f app${RESET}"
echo -e "  Stop    : ${CYAN}docker compose -p ${COMPOSE_PROJECT} down${RESET}"
echo ""
