"""Read-only inventory projections and local observation reconciliation."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Iterable


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_stale(last_seen_at: str | None, *, now: datetime, stale_after_seconds: int) -> bool:
    observed = _parse_time(last_seen_at)
    if observed is None:
        return True
    return (now - observed).total_seconds() > max(1, stale_after_seconds)


def list_inventory(
    conn: sqlite3.Connection,
    *,
    customer_scope: Iterable[str] | None = None,
    state: str | None = None,
    now: datetime | None = None,
    stale_after_seconds: int = 900,
) -> list[dict[str, object]]:
    """Return deployment inventory without contacting a provider.

    A later provider adapter can call :func:`record_observation`; this query
    intentionally makes stale local data visible instead of implying that it
    is current.
    """

    scope = tuple(item.strip() for item in (customer_scope or ()) if item and item.strip())
    clauses = ["1 = 1"]
    params: list[object] = []
    if scope:
        clauses.append("c.external_id IN (" + ", ".join("?" for _ in scope) + ")")
        params.extend(scope)
    if state:
        clauses.append("d.state = ?")
        params.append(state)
    rows = conn.execute(
        f"""
        SELECT d.external_id, d.tenant_id, d.provider, d.region, d.state,
               d.last_seen_at, c.external_id AS customer_external_id,
               v.version AS version,
               MAX(CASE WHEN dom.kind = 'api' THEN dom.hostname END) AS api_domain,
               MAX(CASE WHEN dom.kind = 'console' THEN dom.hostname END) AS console_domain
          FROM cc_deployments d
          JOIN cc_customers c ON c.id = d.customer_id
          LEFT JOIN cc_versions v ON v.id = d.version_id
          LEFT JOIN cc_domains dom ON dom.deployment_id = d.id
         WHERE {' AND '.join(clauses)}
         GROUP BY d.id
         ORDER BY c.external_id, d.external_id
        """,
        tuple(params),
    ).fetchall()
    current = now or datetime.now(timezone.utc)
    return [
        {
            "external_id": row[0],
            "tenant_id": row[1],
            "provider": row[2],
            "region": row[3],
            "state": row[4],
            "last_seen_at": row[5],
            "customer_external_id": row[6],
            "version": row[7],
            "api_domain": row[8],
            "console_domain": row[9],
            "stale": _is_stale(row[5], now=current, stale_after_seconds=stale_after_seconds),
        }
        for row in rows
    ]


def record_observation(
    conn: sqlite3.Connection,
    *,
    deployment_external_id: str,
    provider: str,
    region: str,
    state: str,
    observed_at: str,
) -> None:
    """Persist a provider observation supplied by a future adapter."""

    result = conn.execute(
        """
        UPDATE cc_deployments
           SET provider = ?, region = ?, state = ?, last_seen_at = ?, updated_at = ?
         WHERE external_id = ?
        """,
        (provider, region, state, observed_at, observed_at, deployment_external_id),
    )
    if result.rowcount != 1:
        raise LookupError(deployment_external_id)
    conn.commit()
