#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${ROOT_DIR}/compose/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env.prod}"

if [ ! -f "${ENV_FILE}" ]; then
  echo "ERROR: ${ENV_FILE} not found. Create it before deploying." >&2
  exit 1
fi

required_vars=(
  HP_IMAGE
  APP_VERSION
  HP_PUBLIC_HOST
  ACME_EMAIL
)

missing=()
for v in "${required_vars[@]}"; do
  if ! grep -qE "^${v}=" "${ENV_FILE}"; then
    missing+=("${v}")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: Missing required vars in ${ENV_FILE}: ${missing[*]}" >&2
  exit 1
fi

echo "Deploying from:"
echo "  COMPOSE_FILE=${COMPOSE_FILE}"
echo "  ENV_FILE=${ENV_FILE}"

cd "${ROOT_DIR}"

_infer_ghcr_user() {
  # Best-effort parse from HP_IMAGE=ghcr.io/<user>/<image>
  local img
  img="$(grep -E '^HP_IMAGE=' "${ENV_FILE}" | head -n 1 | cut -d= -f2- | tr -d '\r' || true)"
  img="${img:-}"
  if [[ "${img}" =~ ^ghcr\.io/([^/]+)/.+$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo "${USER:-}"
  return 0
}

_maybe_login_ghcr() {
  local user token
  user="$(_infer_ghcr_user)"
  user="${user:-0x-unkwn0wn}"

  # If GHCR_TOKEN is provided, use it (works without TTY).
  if [[ -n "${GHCR_TOKEN:-}" ]]; then
    printf '%s' "${GHCR_TOKEN}" | docker login ghcr.io -u "${user}" --password-stdin
    return 0
  fi

  # Otherwise, prompt only if we have a TTY.
  if [[ -t 0 ]]; then
    read -r -p "GHCR username [${user}]: " maybe_user
    if [[ -n "${maybe_user:-}" ]]; then
      user="${maybe_user}"
    fi
    read -r -s -p "GHCR token: " token
    echo
    printf '%s' "${token}" | docker login ghcr.io -u "${user}" --password-stdin
    return 0
  fi

  echo "ERROR: GHCR auth required but no TTY available to prompt." >&2
  echo "Set GHCR_TOKEN in the environment and retry, e.g.:" >&2
  echo "  GHCR_TOKEN=... bash ops/vps/deploy.sh" >&2
  return 1
}

echo "Pulling images..."
pull_out=""
if ! pull_out="$(docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" pull 2>&1)"; then
  echo "${pull_out}" >&2
  if echo "${pull_out}" | grep -qiE 'denied|unauthorized|authentication required'; then
    echo "Registry auth failed; attempting GHCR login..." >&2
    _maybe_login_ghcr
    docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" pull
  else
    exit 1
  fi
fi

echo "Starting services..."
docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d --remove-orphans

echo "Pruning unused images..."
docker image prune -f >/dev/null 2>&1 || true

echo "Done."
