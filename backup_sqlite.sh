#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_ROOT/compose/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env.prod}"
APP_DB_PATH="${APP_DB_PATH:-/data/honeypot.db}"
KEEP_DAYS="${KEEP_DAYS:-14}"
MAX_BACKUPS="${MAX_BACKUPS:-60}"
VERIFY_INTEGRITY="${VERIFY_INTEGRITY:-1}"
ENCRYPT="${ENCRYPT:-1}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}" || true

# NOC-026: resolve the *actual* volume/image names Compose would use for
# this project (which depend on the project name docker compose infers --
# see compose/docker-compose.prod.yml's `volumes:` block, which sets no
# explicit `name:`) instead of a hardcoded guess. A stale guess doesn't
# error -- `docker run -v <nonexistent-name>:/data` silently auto-creates
# a fresh EMPTY volume with that name, so a wrong guess looks like a
# successful backup of nothing.
_compose_config() {
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" config --format json
}

DATA_VOLUME="$(_compose_config | python3 -c "import json,sys; print(json.load(sys.stdin)['volumes']['hp_prod_data']['name'])")"
MYAPP_VOLUME="$(_compose_config | python3 -c "import json,sys; print(json.load(sys.stdin)['volumes']['hp_prod_myapp']['name'])")"
APP_IMAGE="$(_compose_config | python3 -c "import json,sys; print(json.load(sys.stdin)['services']['app']['image'])")"

echo "[backup] data volume=${DATA_VOLUME} myapp volume=${MYAPP_VOLUME} image=${APP_IMAGE}" >&2

DB_BACKUP="${BACKUP_DIR}/${TIMESTAMP}-honeypot.db"
MYAPP_BACKUP="${BACKUP_DIR}/${TIMESTAMP}-myapp.tar"

echo "[backup] creating consistent SQLite snapshot ${DB_BACKUP}" >&2
# `sqlite3 .backup` is WAL-safe (SQLite's online backup API) -- it does
# not block or interfere with concurrent writers from app/admin, unlike a
# raw file copy of a WAL-mode database.
docker run --rm \
  -v "${DATA_VOLUME}:/data:ro" \
  -v "${BACKUP_DIR}:/backups" \
  alpine:3 \
  sh -c "set -eu; apk add --no-cache sqlite > /dev/null; sqlite3 ${APP_DB_PATH} \".backup '/backups/$(basename "${DB_BACKUP}")'\""

if [[ "${VERIFY_INTEGRITY}" == "1" ]]; then
  echo "[backup] verifying SQLite integrity" >&2
  docker run --rm \
    -v "${BACKUP_DIR}:/backups" \
    alpine:3 \
    sh -c "set -eu; apk add --no-cache sqlite > /dev/null; sqlite3 '/backups/$(basename "${DB_BACKUP}")' 'PRAGMA integrity_check;'"
fi

echo "[backup] archiving /var/lib/myapp (license + instance-id state) to ${MYAPP_BACKUP}" >&2
docker run --rm \
  -v "${MYAPP_VOLUME}:/var/lib/myapp:ro" \
  -v "${BACKUP_DIR}:/backups" \
  alpine:3 \
  sh -c "tar -C /var/lib/myapp -cf '/backups/$(basename "${MYAPP_BACKUP}")' ."

if [[ "${ENCRYPT}" == "1" ]]; then
  echo "[backup] encrypting backup artifacts (HP_BACKUP_ENCRYPTION_KEY)" >&2
  SECRET_MOUNT=()
  SECRET_ENV=()
  BACKUP_KEY_FILE="${PROJECT_ROOT}/compose/secrets/backup_encryption_key.txt"
  if [[ -f "${BACKUP_KEY_FILE}" ]]; then
    SECRET_MOUNT=(-v "${BACKUP_KEY_FILE}:/run/secrets/backup_encryption_key:ro")
    SECRET_ENV=(-e "HP_BACKUP_ENCRYPTION_KEY_FILE=/run/secrets/backup_encryption_key")
  fi
  for f in "${DB_BACKUP}" "${MYAPP_BACKUP}"; do
    docker run --rm \
      --env-file "${ENV_FILE}" \
      "${SECRET_MOUNT[@]}" "${SECRET_ENV[@]}" \
      -v "${BACKUP_DIR}:/backups" \
      "${APP_IMAGE}" \
      python scripts/backup_tool.py encrypt "/backups/$(basename "$f")" "/backups/$(basename "$f").enc"
    rm -f "$f"
  done
  DB_BACKUP="${DB_BACKUP}.enc"
  MYAPP_BACKUP="${MYAPP_BACKUP}.enc"
else
  echo "[backup] WARNING: ENCRYPT=0 -- backups written in plaintext" >&2
fi

chmod 600 "${DB_BACKUP}" "${MYAPP_BACKUP}" || true

echo "[backup] pruning backups older than ${KEEP_DAYS} days" >&2
find "${BACKUP_DIR}" -maxdepth 1 -type f \( -name "*-honeypot.db*" -o -name "*-myapp.tar*" \) -mtime +"${KEEP_DAYS}" -print -delete

echo "[backup] enforcing a hard cap of ${MAX_BACKUPS} backups per artifact type" >&2
for pattern in "*-honeypot.db*" "*-myapp.tar*"; do
  # shellcheck disable=SC2012
  ls -1t "${BACKUP_DIR}"/${pattern} 2>/dev/null | tail -n +"$((MAX_BACKUPS + 1))" | while IFS= read -r stale; do
    echo "[backup] removing stale backup over MAX_BACKUPS cap: ${stale}" >&2
    rm -f "${stale}"
  done
done

echo "[backup] done: ${DB_BACKUP} ${MYAPP_BACKUP}" >&2
