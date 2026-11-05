"""NOC-025: scripts/merge_actors_by_ua_family.py must read HP_SEED through
app.docker_secrets, not a bare os.getenv -- otherwise a Managed deployment
that only sets HP_SEED_FILE (no plain HP_SEED env var at all, per NOC-023)
would fail this script's own "--seed or HP_SEED required" check even
though the real secret is available.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def test_seed_default_is_read_via_file_when_only_hp_seed_file_is_set():
    repo_root = Path(__file__).resolve().parents[1]
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("a-seed-from-the-docker-secret-file\n")
        seed_file = f.name
    try:
        env = dict(os.environ)
        env.pop("HP_SEED", None)
        env["HP_SEED_FILE"] = seed_file
        result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / "merge_actors_by_ua_family.py"),
             "--db", str(repo_root), "--dry-run"],
            cwd=repo_root, env=env, capture_output=True, text=True, timeout=15,
        )
        # Fails for an unrelated reason (--db points at a directory, not a
        # sqlite file) -- what matters is it never hits the
        # "--seed or HP_SEED required" early-exit this fix targets.
        assert "--seed or HP_SEED required" not in result.stderr
    finally:
        os.unlink(seed_file)


def test_seed_still_required_when_nothing_is_set():
    repo_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env.pop("HP_SEED", None)
    env.pop("HP_SEED_FILE", None)
    result = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "merge_actors_by_ua_family.py"), "--dry-run"],
        cwd=repo_root, env=env, capture_output=True, text=True, timeout=15,
    )
    assert "--seed or HP_SEED required" in result.stderr
    assert result.returncode == 1
