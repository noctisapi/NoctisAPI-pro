# app/panel_membership_audit.py
"""Audit trail for membership changes (NOC-020).

Narrowly scoped to the member-management actions this Issue adds (invite,
role change, deactivate, reactivate, revoke-sessions) -- not the
general-purpose administrative audit log for every console action, which
NOC-021 will design on its own terms. Recording both here and there would
mean guessing at a shape NOC-021 hasn't settled yet; this module only
promises what NOC-020's own acceptance criterion needs: membership changes
are audited and visible.

Used from both the panel UI (app.panel_mvp's /dashboard/members routes)
and scripts/panel_user.py, so an operator's CLI actions and an owner's
in-panel actions land in the same trail.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import List, Optional

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS panel_membership_audit (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at      TEXT NOT NULL,
        actor_username  TEXT NOT NULL,
        action          TEXT NOT NULL,
        target_username TEXT NOT NULL,
        detail          TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_panel_membership_audit_created_at ON panel_membership_audit(created_at)",
]

# Origin label for actions taken through scripts/panel_user.py, where there
# is no logged-in panel identity to attribute the change to.
CLI_ACTOR = "operator-cli"


def ensure_tables(conn: sqlite3.Connection) -> None:
    for stmt in _DDL:
        conn.execute(stmt)
    conn.commit()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def record(
    conn: sqlite3.Connection,
    *,
    actor_username: str,
    action: str,
    target_username: str,
    detail: str = "",
) -> None:
    conn.execute(
        """
        INSERT INTO panel_membership_audit(created_at, actor_username, action, target_username, detail)
        VALUES (?, ?, ?, ?, ?)
        """,
        (_utc_now(), actor_username, action, target_username, detail),
    )
    conn.commit()


def list_recent(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return list(
        conn.execute(
            "SELECT * FROM panel_membership_audit ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    )
