#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
DATA_VOLUME="${DATA_VOLUME:-honey_app_hp_prod_data}"
APP_DB_PATH="${APP_DB_PATH:-/data/honeypot.db}"
KEEP_DAYS="${KEEP_DAYS:-14}"
VERIFY_INTEGRITY="${VERIFY_INTEGRITY:-1}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}-honeypot.db"

mkdir -p "${BACKUP_DIR}"

echo "[backup] creating snapshot ${BACKUP_PATH} from volume ${DATA_VOLUME}" >&2

docker run --rm \
  -v "${DATA_VOLUME}:/data:ro" \
  -v "${BACKUP_DIR}:/backups" \
  alpine:3 \
  sh -c "set -eu; apk add --no-cache sqlite > /dev/null; sqlite3 ${APP_DB_PATH} \".backup '/backups/$(basename \"${BACKUP_PATH}\")'\""

if [[ "${VERIFY_INTEGRITY}" == "1" ]]; then
  echo "[backup] verifying integrity" >&2
  docker run --rm \
    -v "${BACKUP_DIR}:/backups" \
    alpine:3 \
    sh -c "set -eu; apk add --no-cache sqlite > /dev/null; sqlite3 '/backups/$(basename \"${BACKUP_PATH}\")' 'PRAGMA integrity_check;'"
fi

echo "[backup] pruning backups older than ${KEEP_DAYS} days" >&2
find "${BACKUP_DIR}" -type f -name "*-honeypot.db" -mtime +"${KEEP_DAYS}" -print -delete
