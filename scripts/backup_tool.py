#!/usr/bin/env python
"""
Encrypt/decrypt backup artifacts with a dedicated Fernet key (NOC-026).

Deliberately a *different* key from app.log_export_stream's HP_SEED/
HP_SECRETS_KEY-derived Fernet key (used for the system_secrets table) --
a leaked backup encryption key should never also compromise actor/session
identity derivation or the log-export consumer-secret store, and a leaked
HP_SEED shouldn't automatically mean every off-site backup is readable
either. See compose/secrets/README.md for how HP_BACKUP_ENCRYPTION_KEY is
generated and rotated.

Run inside the app image (it already has `cryptography` installed and
this repo on its PYTHONPATH) -- see backup_sqlite.sh / restore_backup.sh,
which invoke this via `docker run ... "${APP_IMAGE}" python scripts/backup_tool.py ...`
rather than adding new tooling to the throwaway alpine container used for
the SQLite/tar steps.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow running from the repo root without needing to pre-set PYTHONPATH
# (the app image already sets PYTHONPATH=/app, so this is a no-op there).
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402

from app import docker_secrets  # noqa: E402


def load_key() -> bytes:
    raw = docker_secrets.read_secret("HP_BACKUP_ENCRYPTION_KEY", "").strip()
    if not raw:
        print("ERROR: HP_BACKUP_ENCRYPTION_KEY is not set (see compose/secrets/README.md)", file=sys.stderr)
        sys.exit(2)
    return raw.encode("ascii")


def encrypt_file(src: Path, dest: Path, key: bytes) -> None:
    fernet = Fernet(key)
    dest.write_bytes(fernet.encrypt(src.read_bytes()))


def decrypt_file(src: Path, dest: Path, key: bytes) -> None:
    fernet = Fernet(key)
    try:
        dest.write_bytes(fernet.decrypt(src.read_bytes()))
    except InvalidToken:
        print(f"ERROR: could not decrypt '{src}' -- wrong key, or the file isn't a valid encrypted backup", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a backup artifact")
    p_enc.add_argument("src", type=Path)
    p_enc.add_argument("dest", type=Path)

    p_dec = sub.add_parser("decrypt", help="Decrypt a backup artifact")
    p_dec.add_argument("src", type=Path)
    p_dec.add_argument("dest", type=Path)

    args = parser.parse_args()
    if not args.src.exists():
        print(f"ERROR: '{args.src}' does not exist", file=sys.stderr)
        return 2

    key = load_key()
    if args.command == "encrypt":
        encrypt_file(args.src, args.dest, key)
    else:
        decrypt_file(args.src, args.dest, key)
    print(f"{args.command}ed: {args.src} -> {args.dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
