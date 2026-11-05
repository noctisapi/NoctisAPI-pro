# app/docker_secrets.py
"""Docker-secret-aware environment variable resolution (NOC-023).

For a value normally read from env var NAME, resolves in this order:
  1. NAME_FILE -- if set, read that file's content (stripped). This is the
     same "_FILE" convention several official Docker images use (e.g.
     postgres's POSTGRES_PASSWORD_FILE) for a Docker Compose `secrets:`
     mount, which lands at /run/secrets/<name> by default.
  2. NAME itself -- the plain env var, unchanged from how self-hosted
     deployments set it in .env.prod today.
  3. default.

Self-hosted customers who only ever set HP_SEED directly are completely
unaffected -- HP_SEED_FILE simply isn't set for them, so this falls
straight through to step 2, identical to the plain os.getenv() it replaces.
"""
from __future__ import annotations

import os


def read_secret(name: str, default: str = "") -> str:
    file_path = os.getenv(f"{name}_FILE", "").strip()
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            pass
    return os.getenv(name, default)
