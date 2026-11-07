"""Commercial read model for the Control Center."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone

from .security import sanitize_audit_details


_CARD_KEYS = frozenset({"card_number", "pan", "cvv", "cvc", "expiration", "expiry"})


class SensitiveBillingDataError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def subscription_summary(
    conn: sqlite3.Connection,
    *,
    customer_scope: Iterable[str] | None = None,
) -> list[dict[str, object]]:
    scope = tuple(item.strip() for item in (customer_scope or ()) if item and item.strip())
    clauses = ["1 = 1"]
    params: list[object] = []
    if scope:
        clauses.append("c.external_id IN (" + ", ".join("?" for _ in scope) + ")")
        params.extend(scope)
    rows = conn.execute(
        f"""
        SELECT s.external_id, c.external_id, s.plan_code, s.commercial_state,
               s.mode, s.entitlement_version, s.starts_at, s.ends_at,
               CASE WHEN s.billing_ref IS NULL OR s.billing_ref = '' THEN 0 ELSE 1 END,
               MAX(e.received_at), SUM(CASE WHEN e.reconciliation_state = 'failed' THEN 1 ELSE 0 END)
          FROM cc_subscriptions s
          JOIN cc_customers c ON c.id = s.customer_id
          LEFT JOIN cc_subscription_events e ON e.subscription_id = s.id
         WHERE {' AND '.join(clauses)}
         GROUP BY s.id
         ORDER BY c.external_id, s.external_id
        """,
        tuple(params),
    ).fetchall()
    return [
        {
            "external_id": row[0],
            "customer_external_id": row[1],
            "plan_code": row[2],
            "commercial_state": row[3],
            "mode": row[4],
            "entitlement_version": row[5],
            "starts_at": row[6],
            "ends_at": row[7],
            "has_billing_reference": bool(row[8]),
            "last_billing_event_at": row[9],
            "failed_reconciliation_count": int(row[10] or 0),
        }
        for row in rows
    ]


def record_billing_event(
    conn: sqlite3.Connection,
    *,
    subscription_external_id: str,
    external_event_id: str,
    provider: str,
    event_type: str,
    applied_state: str | None,
    payload: Mapping[str, object],
) -> int:
    if any(str(key).lower() in _CARD_KEYS for key in payload):
        raise SensitiveBillingDataError("card data is not accepted")
    subscription = conn.execute(
        "SELECT id FROM cc_subscriptions WHERE external_id = ?",
        (subscription_external_id,),
    ).fetchone()
    if subscription is None:
        raise LookupError(subscription_external_id)
    existing = conn.execute(
        "SELECT id FROM cc_subscription_events WHERE external_event_id = ?",
        (external_event_id,),
    ).fetchone()
    if existing:
        return int(existing[0])
    cursor = conn.execute(
        """
        INSERT INTO cc_subscription_events(
          subscription_id, external_event_id, provider, event_type, applied_state,
          reconciliation_state, received_at, details_json
        ) VALUES (?, ?, ?, ?, ?, 'applied', ?, ?)
        """,
        (
            subscription[0], external_event_id, provider, event_type, applied_state,
            _now(), json.dumps(sanitize_audit_details(payload), sort_keys=True),
        ),
    )
    conn.commit()
    return int(cursor.lastrowid)
