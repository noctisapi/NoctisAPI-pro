"""Shared readiness helpers for internal components and healthcheck scripts."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from alembic.config import Config
from alembic.script import ScriptDirectory

DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")
ALEMBIC_INI_PATH = Path(
    os.getenv("ALEMBIC_INI_PATH", Path(__file__).resolve().parent.parent / "alembic.ini")
)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _current_migration_version(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT version_num FROM alembic_version LIMIT 1").fetchone()
    if not row:
        raise RuntimeError("alembic_version table is empty - run migrations")
    version = row["version_num"] if isinstance(row, sqlite3.Row) else row[0]
    if version is None:
        raise RuntimeError("alembic_version returned NULL")
    return str(version)


def _expected_migration_head() -> Tuple[Optional[str], Optional[str]]:
    cfg_path = ALEMBIC_INI_PATH
    if not cfg_path.exists():
        return None, f"Alembic configuration not found at {cfg_path}"

    cfg = Config(str(cfg_path))
    script_location = cfg.get_main_option("script_location")
    if script_location:
        script_path = Path(script_location)
        if not script_path.is_absolute():
            script_path = cfg_path.parent / script_path
            cfg.set_main_option("script_location", str(script_path))

    try:
        script = ScriptDirectory.from_config(cfg)
        return script.get_current_head(), None
    except Exception as exc:  # pragma: no cover - defensive
        return None, str(exc)


def ensure_ready() -> Dict[str, Any]:
    conn = _connect()
    try:
        quick_check_row = conn.execute("PRAGMA quick_check").fetchone()
        quick_check = quick_check_row[0] if quick_check_row else "unknown"
        if quick_check != "ok":
            raise RuntimeError(f"sqlite quick_check returned {quick_check!r}")
        current = _current_migration_version(conn)
    finally:
        conn.close()

    expected, head_error = _expected_migration_head()
    if head_error:
        raise RuntimeError(head_error)
    if expected and current != expected:
        raise RuntimeError(
            f"pending migrations detected (current={current}, expected={expected})"
        )

    return {
        "status": "ready",
        "database_path": DB_PATH,
        "quick_check": quick_check,
        "current_revision": current,
        "expected_revision": expected,
    }


def basic_health() -> bool:
    conn = _connect()
    try:
        conn.execute("SELECT 1")
        return True
    finally:
        conn.close()
