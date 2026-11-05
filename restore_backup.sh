#!/usr/bin/env bash
set -euo pipefail

# Restore a backup produced by backup_sqlite.sh (NOC-026) into a volume.
#
# Usage:
#   ./restore_backup.sh db    backups/20261105T020000Z-honeypot.db.enc
#   ./restore_backup.sh myapp backups/20261105T020000Z-myapp.tar.enc
#
# IMPORTANT: stop the stack first (`docker compose ... down`) -- this
# writes directly into the live volume and does not coordinate with a
# running app/admin/migrate. Start it again afterward.

usage() {
  echo "Usage: $0 <db|myapp> <backup-file>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
KIND="$1"
BACKUP_FILE="$2"
[[ "${KIND}" == "db" || "${KIND}" == "myapp" ]] || usage
[[ -f "${BACKUP_FILE}" ]] || { echo "ERROR: '${BACKUP_FILE}' does not exist" >&2; exit 2; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_ROOT/compose/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env.prod}"
APP_DB_PATH="${APP_DB_PATH:-/data/honeypot.db}"
WORK_DIR="$(dirname "$(cd "$(dirname "${BACKUP_FILE}")" && pwd)/$(basename "${BACKUP_FILE}")")"

_compose_config() {
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" config --format json
}

DATA_VOLUME="$(_compose_config | python3 -c "import json,sys; print(json.load(sys.stdin)['volumes']['hp_prod_data']['name'])")"
MYAPP_VOLUME="$(_compose_config | python3 -c "import json,sys; print(json.load(sys.stdin)['volumes']['hp_prod_myapp']['name'])")"
APP_IMAGE="$(_compose_config | python3 -c "import json,sys; print(json.load(sys.stdin)['services']['app']['image'])")"

# NOC-027: hard check, not just a printed warning -- refuse to restore into
# a volume any container is still actively using. Overwriting a volume
# out from under a running app/admin/migrate is exactly the "accidental
# overwrite" this Issue's acceptance criterion is about; a reminder to
# stop the stack first is not the same as actually enforcing it.
_assert_volume_not_in_use() {
  local volume="$1"
  local using
  using="$(docker ps -q --filter "volume=${volume}")"
  if [[ -n "${using}" ]]; then
    echo "ERROR: volume ${volume} is in use by a running container:" >&2
    docker ps --filter "volume=${volume}" --format '  {{.Names}} ({{.Image}})' >&2
    echo "Stop the stack first: docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} down" >&2
    exit 1
  fi
}

DECRYPTED="${BACKUP_FILE}"
if [[ "${BACKUP_FILE}" == *.enc ]]; then
  DECRYPTED="${BACKUP_FILE%.enc}.restore"
  echo "[restore] decrypting ${BACKUP_FILE} -> ${DECRYPTED}" >&2
  SECRET_MOUNT=()
  SECRET_ENV=()
  BACKUP_KEY_FILE="${PROJECT_ROOT}/compose/secrets/backup_encryption_key.txt"
  if [[ -f "${BACKUP_KEY_FILE}" ]]; then
    SECRET_MOUNT=(-v "${BACKUP_KEY_FILE}:/run/secrets/backup_encryption_key:ro")
    SECRET_ENV=(-e "HP_BACKUP_ENCRYPTION_KEY_FILE=/run/secrets/backup_encryption_key")
  fi
  docker run --rm \
    --env-file "${ENV_FILE}" \
    "${SECRET_MOUNT[@]}" "${SECRET_ENV[@]}" \
    -v "${WORK_DIR}:/backups" \
    "${APP_IMAGE}" \
    python scripts/backup_tool.py decrypt "/backups/$(basename "${BACKUP_FILE}")" "/backups/$(basename "${DECRYPTED}")"
fi

if [[ "${KIND}" == "db" ]]; then
  _assert_volume_not_in_use "${DATA_VOLUME}"
  echo "[restore] WARNING: this overwrites the live database in volume ${DATA_VOLUME}." >&2
  read -r -p "Type 'yes' to continue: " CONFIRM
  [[ "${CONFIRM}" == "yes" ]] || { echo "[restore] aborted" >&2; exit 1; }
  docker run --rm \
    -v "${DATA_VOLUME}:/data" \
    -v "${WORK_DIR}:/backups" \
    alpine:3 \
    sh -c "cp '/backups/$(basename "${DECRYPTED}")' ${APP_DB_PATH}"
  echo "[restore] restored into volume ${DATA_VOLUME} at ${APP_DB_PATH}" >&2
else
  _assert_volume_not_in_use "${MYAPP_VOLUME}"
  echo "[restore] WARNING: this overwrites /var/lib/myapp in volume ${MYAPP_VOLUME}." >&2
  read -r -p "Type 'yes' to continue: " CONFIRM
  [[ "${CONFIRM}" == "yes" ]] || { echo "[restore] aborted" >&2; exit 1; }
  docker run --rm \
    -v "${MYAPP_VOLUME}:/var/lib/myapp" \
    -v "${WORK_DIR}:/backups" \
    alpine:3 \
    sh -c "rm -rf /var/lib/myapp/* && tar -C /var/lib/myapp -xf '/backups/$(basename "${DECRYPTED}")'"
  echo "[restore] restored into volume ${MYAPP_VOLUME}" >&2
fi

if [[ "${DECRYPTED}" != "${BACKUP_FILE}" ]]; then
  rm -f "${DECRYPTED}"
fi

echo "[restore] done. Start the stack again: docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d" >&2
