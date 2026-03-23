#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${NOCTISAPI_BASE_URL:-https://get.noctisapi.com}"
INSTALL_DIR="${NOCTISAPI_DIR:-/opt/noctisapi}"

echo ""
echo "  NoctisAPI PRO"
echo "  ─────────────"
echo ""

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not installed." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose plugin not found." >&2; exit 1; }

mkdir -p "${INSTALL_DIR}" && cd "${INSTALL_DIR}"

# ── prompt for the only two values that can't be defaulted ───────────────────
read -r -p "  Public API domain (e.g. api.example.com): " HP_PUBLIC_HOST
while [[ -z "${HP_PUBLIC_HOST}" ]]; do
  read -r -p "  Public API domain (required): " HP_PUBLIC_HOST
done

read -r -p "  Let's Encrypt email: " ACME_EMAIL
while [[ -z "${ACME_EMAIL}" ]]; do
  read -r -p "  Let's Encrypt email (required): " ACME_EMAIL
done

HP_SEED="$(openssl rand -hex 32)"

# ── download files if not already present ────────────────────────────────────
[[ -f docker-compose.yml ]] || curl -fsSL "${BASE_URL}/docker-compose.yml" -o docker-compose.yml
mkdir -p data/siem

# ── write .env ────────────────────────────────────────────────────────────────
if [[ -f .env ]]; then
  echo ""
  echo "  .env already exists — skipping. Delete it and re-run to reconfigure."
else
  cat > .env <<ENVEOF
HP_IMAGE=noctisapi/noctisapi-pro
APP_VERSION=latest
APP_ENV=prod
HP_PUBLIC_HOST=${HP_PUBLIC_HOST}
ACME_EMAIL=${ACME_EMAIL}
HP_SEED=${HP_SEED}
DATABASE_URL=sqlite+pysqlite:////data/honeypot.db
MAXMIND_ACCOUNT_ID=
MAXMIND_LICENSE_KEY=
HP_ENFORCE_LICENSE=1
LOG_LEVEL=info
ENVEOF
  chmod 600 .env
fi

# ── start ─────────────────────────────────────────────────────────────────────
echo ""
docker compose up -d

echo ""
echo "  Honeypot API  : https://${HP_PUBLIC_HOST}"
echo "  Admin panel   : http://localhost:9001  (SSH tunnel: ssh -L 9001:localhost:9001 user@server)"
echo ""
