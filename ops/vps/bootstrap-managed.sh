#!/usr/bin/env bash
set -euo pipefail

# NOC-033: the application-specific half of a Managed instance's
# cloud-init bootstrap. The OS-level half (packages, the admin user,
# SSH hardening, Docker install, ufw, cloning the repo, staging
# .env.prod) is cloud-init's own job (terraform/hetzner/templates/
# cloud-init.yaml.tftpl) -- by the time this script runs, /opt/hp-app
# is a cloned checkout with .env.prod already in place. Everything
# from here on is ordinary, reviewable, independently-testable bash
# rather than logic embedded in YAML.
#
# Reads HP_CUSTOMER_ID / HP_REGION / HP_SIZING / HP_PLAN / HP_PUBLIC_HOST
# / HP_ADMIN_HOST from the environment (set by the cloud-init runcmd
# line that invokes this script) -- none of those are secrets (see
# scripts/deployment_manifest.py's own sensitive-key check, NOC-031).
# The one secret this script touches (GHCR_TOKEN) is read from a FILE
# path, never passed as a command-line argument or env var literal, so
# it never appears in a logged command line -- see the GHCR section
# below and cloud-init.yaml.tftpl's matching write_files entry.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

LOG="/var/log/noctisapi-bootstrap.log"
STATUS_FILE="${ROOT_DIR}/.bootstrap-status"
GHCR_TOKEN_FILE="/root/.ghcr-token"

_log() {
  echo "[bootstrap] $*" | tee -a "${LOG}"
}

_fail() {
  _log "FAILED: $*"
  echo "failed: $*" > "${STATUS_FILE}"
  exit 1
}
trap '_fail "unexpected error at line $LINENO"' ERR

_log "starting (deployment for customer_id=${HP_CUSTOMER_ID:-<none>})"

_log "data directories"
mkdir -p "${ROOT_DIR}/data/siem"
chown -R 10001:0 "${ROOT_DIR}/data/siem"
chmod 775 "${ROOT_DIR}/data/siem"

# Created now, not left for the first cron run (ops/cron/noctisapi-backup,
# DEPLOY.md Sec11b) to create implicitly -- scripts/ops_monitor.py's disk
# check below needs an existing path to stat, and backup_sqlite.sh's own
# `mkdir -p "${BACKUP_DIR}"` wouldn't run until the first scheduled backup,
# hours after this script finishes. Caught by actually running this
# against a live stack, not by reasoning about it.
mkdir -p "${ROOT_DIR}/backups"
chmod 700 "${ROOT_DIR}/backups"

_log "per-deployment secrets and manifest (scripts/init_deployment.py, NOC-025/031)"
python3 scripts/init_deployment.py \
  --public-host "${HP_PUBLIC_HOST:-}" \
  --admin-host "${HP_ADMIN_HOST:-}" \
  --customer-id "${HP_CUSTOMER_ID:-}" \
  --region "${HP_REGION:-}" \
  --sizing "${HP_SIZING:-}" \
  --plan "${HP_PLAN:-}" \
  >>"${LOG}" 2>&1

if [[ -f "${GHCR_TOKEN_FILE}" ]]; then
  _log "authenticating to GHCR (token read from a file, never from argv/env literal)"
  printf '%s' "$(cat "${GHCR_TOKEN_FILE}")" \
    | docker login ghcr.io -u "${GHCR_USER:-0x-unkwn0wn}" --password-stdin >>"${LOG}" 2>&1
  shred -u "${GHCR_TOKEN_FILE}" 2>/dev/null || rm -f "${GHCR_TOKEN_FILE}"
fi

_log "pulling and starting the managed stack"
docker compose --env-file .env.prod \
  -f compose/docker-compose.prod.yml -f compose/docker-compose.managed.yml \
  pull >>"${LOG}" 2>&1
docker compose --env-file .env.prod \
  -f compose/docker-compose.prod.yml -f compose/docker-compose.managed.yml \
  up -d >>"${LOG}" 2>&1

_log "installing the systemd unit so the stack survives a reboot"
cp "${ROOT_DIR}/ops/vps/hp-app.service" /etc/systemd/system/hp-app.service
systemctl daemon-reload
systemctl enable hp-app.service >>"${LOG}" 2>&1

_log "first check (scripts/ops_monitor.py, NOC-028/033) -- containers/disk/memory/cpu only;"
_log "DNS/TLS/certificate and backup freshness are skipped here on purpose: DNS for"
_log "HP_PUBLIC_HOST/HP_ADMIN_HOST has not necessarily been pointed at this VPS yet"
_log "(that is a separate, external step -- DEPLOY.md Sec3b), and no backup has run yet"
_log "on a same-day fresh install. ops_monitor.py's own cron job covers those once the"
_log "instance has been running for a while."
if python3 scripts/ops_monitor.py --managed --skip-certificate --skip-backup-freshness >>"${LOG}" 2>&1; then
  _log "SUCCESS"
  echo "ok" > "${STATUS_FILE}"
else
  _fail "scripts/ops_monitor.py reported a failing check -- see ${LOG}"
fi
