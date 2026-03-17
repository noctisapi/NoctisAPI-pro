#!/usr/bin/env bash
# NoctisAPI PRO — zero-friction installer
# ─────────────────────────────────────────────────────────────────────────────
# Usage (from repo root on the VPS):
#   bash ops/vps/install.sh
#
# Re-running is safe:
#   - If .env.prod already exists, the wizard is skipped and deploy runs.
#   - Delete .env.prod to reconfigure from scratch.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env.prod"
ENV_EXAMPLE="${ROOT_DIR}/.env.prod.example"

# ── helpers ──────────────────────────────────────────────────────────────────
_ask() {
  local prompt="$1" default="${2:-}" answer
  if [[ -n "${default}" ]]; then
    read -r -p "  ${prompt} [${default}]: " answer
    echo "${answer:-${default}}"
  else
    while true; do
      read -r -p "  ${prompt}: " answer
      [[ -n "${answer}" ]] && { echo "${answer}"; return; }
      echo "    (required — cannot be empty)" >&2
    done
  fi
}

_ask_secret() {
  local prompt="$1" answer
  read -r -s -p "  ${prompt} (hidden): " answer
  echo >&2
  echo "${answer}"
}

_ask_optional() {
  local prompt="$1" answer
  read -r -p "  ${prompt} [leave blank to skip]: " answer
  echo "${answer:-}"
}

_ask_optional_secret() {
  local prompt="$1" answer
  read -r -s -p "  ${prompt} (hidden, blank to skip): " answer
  echo >&2
  echo "${answer:-}"
}

_sed_inplace() {
  # portable sed -i for both GNU and BSD
  sed -i "s|$1|$2|" "${ENV_FILE}"
}

_append() {
  echo "$1" >> "${ENV_FILE}"
}

# ── prereqs ───────────────────────────────────────────────────────────────────
echo ""
echo "  NoctisAPI PRO — Installation Wizard"
echo "  ════════════════════════════════════"
echo ""

if ! command -v docker >/dev/null 2>&1; then
  echo "  ERROR: docker is not installed." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "  ERROR: docker compose plugin not found (requires Docker 20.10+)." >&2
  exit 1
fi

# ── skip wizard if .env.prod already exists ───────────────────────────────────
if [[ -f "${ENV_FILE}" ]]; then
  echo "  .env.prod already exists — skipping wizard."
  echo "  Delete ${ENV_FILE} and re-run to reconfigure."
  echo ""
else
  # ── required values ─────────────────────────────────────────────────────────
  echo "  Required values"
  echo "  ───────────────"
  HP_IMAGE=$(_ask     "Docker image"                "ghcr.io/noctisapi/noctisapi-pro")
  APP_VERSION=$(_ask  "Image tag / version"         "latest")
  HP_PUBLIC_HOST=$(_ask "Public API domain"         "")
  ACME_EMAIL=$(_ask   "Let's Encrypt email"         "")
  HP_DEPLOYMENT_ID=$(_ask "Deployment label"        "prod-001")

  # ── auto-generate HP_SEED ───────────────────────────────────────────────────
  HP_SEED="$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
           || openssl rand -hex 32)"
  echo "  HP_SEED: auto-generated."

  # ── optional: registry auth ─────────────────────────────────────────────────
  echo ""
  echo "  Registry auth (skip if image is public)"
  echo "  ────────────────────────────────────────"
  GHCR_TOKEN=$(_ask_optional_secret "GHCR personal access token")

  # ── optional: GeoIP ─────────────────────────────────────────────────────────
  echo ""
  echo "  MaxMind GeoLite2 (optional — skip to disable IP geolocation)"
  echo "  Free account: https://www.maxmind.com/en/geolite2/signup"
  echo "  ─────────────────────────────────────────────────────────────"
  MAXMIND_ACCOUNT_ID=$(_ask_optional "MaxMind Account ID")
  if [[ -n "${MAXMIND_ACCOUNT_ID}" ]]; then
    MAXMIND_LICENSE_KEY=$(_ask_optional_secret "MaxMind License Key")
  else
    MAXMIND_LICENSE_KEY=""
  fi

  # ── write .env.prod ──────────────────────────────────────────────────────────
  echo ""
  echo "  Writing ${ENV_FILE}…"
  cp "${ENV_EXAMPLE}" "${ENV_FILE}"

  _sed_inplace "^HP_IMAGE=.*"                   "HP_IMAGE=${HP_IMAGE}"
  _sed_inplace "^APP_VERSION=.*"                "APP_VERSION=${APP_VERSION}"
  _sed_inplace "^HP_PUBLIC_HOST=.*"             "HP_PUBLIC_HOST=${HP_PUBLIC_HOST}"
  _sed_inplace "^HP_ADMIN_HOST=.*"              "#HP_ADMIN_HOST="
  _sed_inplace "^HP_PUBLIC_BASE_URL=.*"         "HP_PUBLIC_BASE_URL=https://${HP_PUBLIC_HOST}"
  _sed_inplace "^HONEYPOT_PUBLIC_BASE_URL=.*"   "HONEYPOT_PUBLIC_BASE_URL=https://${HP_PUBLIC_HOST}"
  _sed_inplace "^ACME_EMAIL=.*"                 "ACME_EMAIL=${ACME_EMAIL}"
  _sed_inplace "^HP_SEED=.*"                    "HP_SEED=${HP_SEED}"
  _sed_inplace "^HP_DEPLOYMENT_ID=.*"           "HP_DEPLOYMENT_ID=${HP_DEPLOYMENT_ID}"
  _sed_inplace "^MAXMIND_ACCOUNT_ID=.*"         "MAXMIND_ACCOUNT_ID=${MAXMIND_ACCOUNT_ID}"
  _sed_inplace "^MAXMIND_LICENSE_KEY=.*"        "MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY}"

  [[ -n "${GHCR_TOKEN}" ]] && _append "GHCR_TOKEN=${GHCR_TOKEN}"

  chmod 600 "${ENV_FILE}"
  echo "  .env.prod written (mode 600)."
fi

# ── deploy ────────────────────────────────────────────────────────────────────
echo "  Starting deploy…"
echo ""
GHCR_TOKEN="${GHCR_TOKEN:-}" bash "${SCRIPT_DIR}/deploy.sh"

echo ""
echo "  Done."
echo ""
HP_PUBLIC_HOST_DISPLAY="$(grep -E '^HP_PUBLIC_HOST=' "${ENV_FILE}" | cut -d= -f2- | tr -d '\r' || echo '?')"
echo "  Honeypot API  : https://${HP_PUBLIC_HOST_DISPLAY}"
echo "  Admin panel   : http://localhost:9001/dashboard  (via SSH tunnel)"
echo ""
