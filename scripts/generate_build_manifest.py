#!/usr/bin/env python3
"""
generate_build_manifest.py — Generate app/build_manifest.py with SHA-256 hashes
of critical Pro licensing source files.

Add this to the Dockerfile as a build step, AFTER copying all source files:

    RUN python scripts/generate_build_manifest.py

The generated app/build_manifest.py is then baked into the image and read by
app/source_integrity.py at container startup to detect tampered source files.

Run from the repository root (/app inside Docker):
    python scripts/generate_build_manifest.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent

CRITICAL_FILES = [
    "honey_licensing/feature_flags.py",
    "honey_licensing/offline_license.py",
    "app/pro_license.py",
    "app/pro_ops.py",
    "app/source_integrity.py",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    print("Generating build manifest...")
    hashes: dict[str, str] = {}
    missing: list[str] = []

    for rel in CRITICAL_FILES:
        abs_path = APP_ROOT / rel
        if not abs_path.exists():
            print(f"  WARNING: {rel} not found — skipping", file=sys.stderr)
            missing.append(rel)
            continue
        digest = sha256_file(abs_path)
        hashes[rel] = digest
        print(f"  {digest[:16]}...  {rel}")

    if missing:
        print(
            f"\nWARNING: {len(missing)} file(s) not found and excluded from the manifest.",
            file=sys.stderr,
        )

    out_path = APP_ROOT / "app" / "build_manifest.py"
    lines = [
        '"""',
        "build_manifest.py — Auto-generated at Docker image build time.",
        "DO NOT EDIT MANUALLY. Regenerate with: python scripts/generate_build_manifest.py",
        '"""',
        "# fmt: off",
        "EXPECTED_HASHES: dict[str, str] = {",
    ]
    for rel in CRITICAL_FILES:
        digest = hashes.get(rel)
        if digest:
            lines.append(f'    "{rel}": "{digest}",')
    lines.append("}")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nWrote {out_path} ({len(hashes)} entries)")


if __name__ == "__main__":
    main()
