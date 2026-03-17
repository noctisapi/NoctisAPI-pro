#!/usr/bin/env python3
"""Download GeoLite2-Country.mmdb from MaxMind into the data volume.

Called automatically by the migrate service at startup. Skips if the file
already exists (re-run ops/geoip/update_geoip.sh to force-refresh).

Required env vars (optional overall — geo enrichment is disabled if missing):
  MAXMIND_ACCOUNT_ID
  MAXMIND_LICENSE_KEY

Optional:
  GEOIP_DEST  — destination path (default: /data/GeoLite2-Country.mmdb)
"""

import os
import sys
import tarfile
import shutil
import tempfile
import urllib.request
import urllib.error

EDITION = "GeoLite2-Country"
account_id = os.environ.get("MAXMIND_ACCOUNT_ID", "").strip()
license_key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
dest = os.environ.get("GEOIP_DEST", "/data/GeoLite2-Country.mmdb").strip()

if not account_id or not license_key:
    print("download_geoip: MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY not set — skipping.")
    sys.exit(0)

if os.path.exists(dest):
    print(f"download_geoip: {dest} already present — skipping (run update_geoip.sh to refresh).")
    sys.exit(0)

url = (
    "https://download.maxmind.com/app/geoip_download"
    f"?edition_id={EDITION}&license_key={license_key}&suffix=tar.gz&account_id={account_id}"
)

print(f"download_geoip: downloading {EDITION}…")
try:
    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "geoip.tar.gz")
        try:
            urllib.request.urlretrieve(url, archive)
        except urllib.error.HTTPError as e:
            print(f"download_geoip: HTTP {e.code} — check MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY.", file=sys.stderr)
            sys.exit(1)

        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith(".mmdb"):
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    tmp_dest = dest + ".tmp"
                    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
                    with open(tmp_dest, "wb") as out:
                        shutil.copyfileobj(f, out)
                    os.replace(tmp_dest, dest)
                    print(f"download_geoip: saved to {dest}")
                    sys.exit(0)

        print("download_geoip: ERROR — .mmdb not found in archive.", file=sys.stderr)
        sys.exit(1)
except Exception as e:
    print(f"download_geoip: unexpected error — {e}", file=sys.stderr)
    sys.exit(1)
