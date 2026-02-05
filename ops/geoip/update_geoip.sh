#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="${DEST_DIR:-/opt/hp-app/data}"
ACCOUNT_ID="${MAXMIND_ACCOUNT_ID:-}"
LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"
EDITION_ID="${MAXMIND_EDITION_ID:-GeoLite2-Country}"

if [ -z "${ACCOUNT_ID}" ] || [ -z "${LICENSE_KEY}" ]; then
  echo "ERROR: MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY are required." >&2
  exit 1
fi

mkdir -p "${DEST_DIR}"
tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

url="https://download.maxmind.com/app/geoip_download?edition_id=${EDITION_ID}&license_key=${LICENSE_KEY}&suffix=tar.gz&account_id=${ACCOUNT_ID}"
echo "Downloading ${EDITION_ID}..."
curl -fsSL "${url}" -o "${tmp_dir}/geoip.tar.gz"

tar -xzf "${tmp_dir}/geoip.tar.gz" -C "${tmp_dir}"
mmdb_path="$(find "${tmp_dir}" -name 'GeoLite2-Country.mmdb' | head -n1)"
if [ -z "${mmdb_path}" ]; then
  echo "ERROR: GeoLite2-Country.mmdb not found in archive." >&2
  exit 1
fi

cp "${mmdb_path}" "${DEST_DIR}/GeoLite2-Country.mmdb"
echo "Saved to ${DEST_DIR}/GeoLite2-Country.mmdb"
