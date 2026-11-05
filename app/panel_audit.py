# app/panel_audit.py
"""General administrative audit log for the panel (NOC-021).

Attributes critical changes and authorization failures to concrete
identities -- "who did what, when, with what result" -- not the narrow,
richly-detailed membership-change trail NOC-020 already built
(app.panel_membership_audit), which keeps its own separate record for
invite/role/deactivate events. This module is coarser-grained but covers
*every* route: method + path + final HTTP status, recorded centrally by
app.panel_mvp's _PanelAuditMiddleware, never the request/response body,
headers, or query string -- so a token or password can never end up in a
row here even by accident. Only requests that are either non-GET (a
"change") or denied by RBAC with 403 (an authorization failure) are
recorded; successful plain reads are not, to keep this a meaningful trail
rather than a full access log.

Retention is handled by scripts/prune_retention.py (HP_RETENTION_PANEL_AUDIT_DAYS,
default 180 days) alongside the other tables it already prunes. Read access
in the panel is ADMIN-tier (GET /dashboard/audit-log, app.panel_rbac).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import List, Optional

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS panel_audit_log (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at     TEXT NOT NULL,
        request_id     TEXT NOT NULL,
        actor_username TEXT,
        actor_role     TEXT,
        method         TEXT NOT NULL,
        path           TEXT NOT NULL,
        status_code    INTEGER
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_panel_audit_log_created_at ON panel_audit_log(created_at)",
    "CREATE INDEX IF NOT EXISTS ix_panel_audit_log_status_code ON panel_audit_log(status_code)",
]


def ensure_tables(conn: sqlite3.Connection) -> None:
    for stmt in _DDL:
        conn.execute(stmt)
    conn.commit()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def should_record(method: str, status_code: Optional[int]) -> bool:
    """A "critical change" (anything not a plain read) or an authorization
    failure (403, from app.panel_mvp._PanelRBACMiddleware) -- not every
    successful read, to keep this a meaningful trail."""
    return method.upper() != "GET" or status_code == 403


def record(
    conn: sqlite3.Connection,
    *,
    request_id: str,
    actor_username: Optional[str],
    actor_role: Optional[str],
    method: str,
    path: str,
    status_code: Optional[int],
) -> None:
    conn.execute(
        """
        INSERT INTO panel_audit_log(created_at, request_id, actor_username, actor_role, method, path, status_code)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (_utc_now(), request_id, actor_username, actor_role, method.upper(), path, status_code),
    )
    conn.commit()


def list_recent(conn: sqlite3.Connection, *, limit: int = 100, failures_only: bool = False) -> List[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    if failures_only:
        return list(
            conn.execute(
                "SELECT * FROM panel_audit_log WHERE status_code >= 400 ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        )
    return list(conn.execute("SELECT * FROM panel_audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall())
