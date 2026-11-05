#!/usr/bin/env python
"""
Initialize (or verify) a Managed instance's per-deployment secret and
non-secret manifest (NOC-025).

Separates two things that must never be conflated into the same file:

  - compose/secrets/hp_seed.txt -- the one secret this generates.
    NEVER regenerated once it exists unless you explicitly pass
    --force-regenerate-seed: HP_SEED must survive every upgrade/reinstall
    (changing it breaks actor/session identity continuity for every
    record this instance has ever recorded -- see CLAUDE.md).

  - compose/secrets/deployment-manifest.json -- everything else about
    this install that ISN'T a secret: a random, non-secret deployment_id,
    when it was created, and which domains it's configured for. Safe to
    log, display, or paste into a support ticket -- it never holds a
    credential, which is exactly why it's a separate file from the one
    above rather than one combined "deployment config" blob.

Idempotent: safe to re-run after every deploy/upgrade. Re-running updates
the manifest's host fields and `updated_at`, but never touches an
existing seed or the manifest's `deployment_id`/`created_at`.

Examples:
  python scripts/init_deployment.py --public-host api-acme.com --admin-host admin.acme.com
  python scripts/init_deployment.py   # re-run after an upgrade; no-op on the seed
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_SECRETS_DIR = _REPO_ROOT / "compose" / "secrets"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_hp_seed(path: Path, *, force: bool = False) -> Tuple[str, bool]:
    """Returns (status message, changed). Never overwrites an existing
    seed unless force=True."""
    if path.exists() and not force:
        return "already exists, left unchanged", False
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best-effort -- not all filesystems (e.g. Windows dev) support this
    return ("regenerated (--force-regenerate-seed)" if force else "generated"), True


def load_manifest(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"deployment_id": uuid.uuid4().hex, "created_at": _utc_now()}


def update_manifest(path: Path, *, public_host: str, admin_host: str) -> dict:
    manifest = load_manifest(path)
    manifest["updated_at"] = _utc_now()
    if public_host:
        manifest["hp_public_host"] = public_host
    if admin_host:
        manifest["hp_admin_host"] = admin_host
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--secrets-dir", default=str(_DEFAULT_SECRETS_DIR))
    parser.add_argument("--public-host", default=os.getenv("HP_PUBLIC_HOST", "").strip())
    parser.add_argument("--admin-host", default=os.getenv("HP_ADMIN_HOST", "").strip())
    parser.add_argument(
        "--force-regenerate-seed",
        action="store_true",
        help=(
            "DANGEROUS: overwrite an existing HP_SEED. Breaks actor/session identity "
            "continuity for every record this instance has ever made. Only appropriate "
            "before a real deployment goes live, or when deliberately accepting that "
            "loss (e.g. decommissioning)."
        ),
    )
    args = parser.parse_args()

    secrets_dir = Path(args.secrets_dir)
    seed_path = secrets_dir / "hp_seed.txt"
    manifest_path = secrets_dir / "deployment-manifest.json"

    seed_status, seed_changed = ensure_hp_seed(seed_path, force=args.force_regenerate_seed)
    if seed_changed and args.force_regenerate_seed:
        print(
            f"WARNING: HP_SEED {seed_status} at {seed_path} -- actor/session continuity reset.",
            file=sys.stderr,
        )
    print(f"hp_seed.txt: {seed_status} ({seed_path})")

    manifest = update_manifest(manifest_path, public_host=args.public_host, admin_host=args.admin_host)
    print(f"deployment-manifest.json: deployment_id={manifest['deployment_id']} ({manifest_path})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
