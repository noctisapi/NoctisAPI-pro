"""Local customer/contract CRUD for the Control Center.

The functions accept an existing SQLite connection so callers can compose
them with the application's transaction and audit boundaries.  They do not
perform network calls and never return another customer's records when a
``customer_scope`` is supplied.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Iterable, Mapping

from .security import sanitize_audit_details


class CustomerNotFound(LookupError):
    pass


class CustomerScopeError(PermissionError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _scope_sql(customer_scope: Iterable[str] | None) -> tuple[str, tuple[str, ...]]:
    scope = tuple(item.strip() for item in (customer_scope or ()) if item and item.strip())
    if not scope:
        return "", ()
    placeholders = ", ".join("?" for _ in scope)
    return f" AND c.external_id IN ({placeholders})", scope


def _audit(
    conn: sqlite3.Connection,
    *,
    actor_ref: str,
    action: str,
    entity_type: str,
    entity_id: str,
    details: Mapping[str, object] | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO cc_audit_log(actor_ref, action, entity_type, entity_id, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor_ref,
            action,
            entity_type,
            entity_id,
            json.dumps(sanitize_audit_details(details or {}), sort_keys=True),
            _now(),
        ),
    )


def create_customer(
    conn: sqlite3.Connection,
    *,
    external_id: str,
    legal_name: str,
    actor_ref: str,
    status: str = "active",
    billing_ref: str | None = None,
    notes: str | None = None,
) -> int:
    now = _now()
    cursor = conn.execute(
        """
        INSERT INTO cc_customers(external_id, legal_name, status, billing_ref, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (external_id.strip(), legal_name.strip(), status, billing_ref, notes, now, now),
    )
    customer_id = int(cursor.lastrowid)
    _audit(
        conn,
        actor_ref=actor_ref,
        action="create",
        entity_type="customer",
        entity_id=external_id,
        details={"legal_name": legal_name, "status": status},
    )
    conn.commit()
    return customer_id


def list_customers(
    conn: sqlite3.Connection,
    *,
    customer_scope: Iterable[str] | None = None,
) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    suffix, scope = _scope_sql(customer_scope)
    return list(
        conn.execute(
            "SELECT c.* FROM cc_customers c WHERE 1 = 1" + suffix + " ORDER BY c.legal_name",
            scope,
        ).fetchall()
    )


def get_customer(
    conn: sqlite3.Connection,
    customer_id: int,
    *,
    customer_scope: Iterable[str] | None = None,
) -> sqlite3.Row:
    conn.row_factory = sqlite3.Row
    suffix, scope = _scope_sql(customer_scope)
    row = conn.execute(
        "SELECT c.* FROM cc_customers c WHERE c.id = ?" + suffix,
        (customer_id, *scope),
    ).fetchone()
    if row is None:
        raise CustomerNotFound(customer_id)
    return row


def update_customer(
    conn: sqlite3.Connection,
    customer_id: int,
    *,
    actor_ref: str,
    customer_scope: Iterable[str] | None = None,
    legal_name: str | None = None,
    status: str | None = None,
    billing_ref: str | None = None,
    notes: str | None = None,
) -> sqlite3.Row:
    current = get_customer(conn, customer_id, customer_scope=customer_scope)
    values = {
        "legal_name": current["legal_name"] if legal_name is None else legal_name.strip(),
        "status": current["status"] if status is None else status,
        "billing_ref": current["billing_ref"] if billing_ref is None else billing_ref,
        "notes": current["notes"] if notes is None else notes,
    }
    conn.execute(
        "UPDATE cc_customers SET legal_name = ?, status = ?, billing_ref = ?, notes = ?, updated_at = ? WHERE id = ?",
        (values["legal_name"], values["status"], values["billing_ref"], values["notes"], _now(), customer_id),
    )
    _audit(conn, actor_ref=actor_ref, action="update", entity_type="customer", entity_id=str(customer_id), details=values)
    conn.commit()
    return get_customer(conn, customer_id, customer_scope=customer_scope)
