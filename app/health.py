"""Lightweight health, readiness, and version checks.

This module provides three pure functions consumed by the FastAPI route
handlers in honeypot_public.py.  All functions are synchronous and
dependency-free (no FastAPI, no HTTP) so they can be unit-tested without
spinning up an ASGI application.

/health  → liveness()   — no I/O; pure process-alive signal
/ready   → readiness()  — single lightweight SQLite SELECT to confirm
                           the DB file is reachable and the schema is
                           initialised; no external services contacted
/version → version_info() — reads env vars set at build / deploy time
"""

from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict


# ---------------------------------------------------------------------------
# Liveness
# ---------------------------------------------------------------------------


def liveness() -> Dict[str, Any]:
    """Return a minimal liveness payload.

    Always succeeds as long as the Python process is running.  No I/O.
    """
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------

_READY_QUERY = "SELECT 1 FROM alembic_version LIMIT 1"


def readiness(db_path: str) -> Dict[str, Any]:
    """Verify that the SQLite database is reachable and the schema exists.

    Returns a dict with ``status`` either ``"ok"`` or ``"degraded"`` and a
    ``checks`` sub-dict describing individual dependency states.

    Raises nothing — degraded state is expressed in the return value so the
    caller controls the HTTP status code.
    """
    t0 = time.perf_counter()
    db_status = "ok"
    db_error: str = ""

    try:
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=2.0)
        try:
            conn.execute("PRAGMA busy_timeout=2000;")
            conn.execute(_READY_QUERY)
        finally:
            conn.close()
    except Exception as exc:
        db_status = "error"
        db_error = type(exc).__name__

    latency_ms = int((time.perf_counter() - t0) * 1000)
    overall = "ok" if db_status == "ok" else "degraded"

    result: Dict[str, Any] = {
        "status": overall,
        "checks": {
            "database": db_status,
        },
        "latency_ms": latency_ms,
    }
    if db_error:
        result["checks"]["database_error"] = db_error
    return result


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

# Build metadata is injected via environment variables at image-build time
# or set in docker-compose / .env.prod.  All fields are optional; missing
# values are returned as empty strings so the response shape stays stable.
_VERSION_VARS = (
    "APP_VERSION",      # application semver (e.g. "0.1.0")
    "HP_API_VERSION",   # honeypot-specific API version (fallback)
    "APP_ENV",          # deployment environment (prod / staging / dev)
    "BUILD_SHA",        # git commit SHA injected by CI
    "BUILD_TIME",       # ISO-8601 build timestamp injected by CI
)


def version_info() -> Dict[str, Any]:
    """Return application version and build metadata.

    All values come from environment variables; no I/O performed.
    """
    version = (
        os.environ.get("APP_VERSION")
        or os.environ.get("HP_API_VERSION")
        or ""
    ).strip()
    env = (os.environ.get("APP_ENV") or "").strip()
    build_sha = (os.environ.get("BUILD_SHA") or "").strip()
    build_time = (os.environ.get("BUILD_TIME") or "").strip()

    return {
        "version": version,
        "env": env,
        "build_sha": build_sha,
        "build_time": build_time,
    }
