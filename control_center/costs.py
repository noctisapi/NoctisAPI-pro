"""Cost attribution and budget alerts for Control Center."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def record_cost(
    conn: sqlite3.Connection,
    *,
    deployment_id: str,
    provider: str,
    period_start: str,
    period_end: str,
    amount_cents: int,
    currency: str,
    source: str,
) -> int:
    deployment = conn.execute("SELECT id FROM cc_deployments WHERE external_id = ?", (deployment_id,)).fetchone()
    if deployment is None:
        raise LookupError(deployment_id)
    cursor = conn.execute(
        """
        INSERT INTO cc_infra_costs(
          deployment_id, provider, period_start, period_end, amount_cents,
          currency, estimate_source, captured_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (deployment[0], provider, period_start, period_end, amount_cents, currency, source, _now()),
    )
    conn.commit()
    return int(cursor.lastrowid)


def budget_alert(
    conn: sqlite3.Connection,
    *,
    customer_external_id: str,
    period_start: str,
    period_end: str,
) -> dict[str, object] | None:
    budget = conn.execute(
        """
        SELECT b.budget_cents, b.warning_pct, b.critical_pct
          FROM cc_cost_budgets b
          JOIN cc_customers c ON c.id = b.customer_id
         WHERE c.external_id = ? AND b.period_start = ? AND b.period_end = ?
        """,
        (customer_external_id, period_start, period_end),
    ).fetchone()
    if budget is None:
        return None
    actual, estimated = conn.execute(
        """
        SELECT
          COALESCE(SUM(CASE WHEN i.estimate_source IN ('invoiced', 'actual', 'factured') THEN i.amount_cents ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN i.estimate_source NOT IN ('invoiced', 'actual', 'factured') THEN i.amount_cents ELSE 0 END), 0)
          FROM cc_infra_costs i
          JOIN cc_deployments d ON d.id = i.deployment_id
          JOIN cc_customers c ON c.id = d.customer_id
         WHERE c.external_id = ? AND i.period_start >= ? AND i.period_end <= ?
        """,
        (customer_external_id, period_start, period_end),
    ).fetchone()
    total = int(actual) + int(estimated)
    percentage = (total * 100 / budget[0]) if budget[0] else 100.0
    level = "critical" if percentage >= budget[2] else "warning" if percentage >= budget[1] else "ok"
    return {
        "customer_external_id": customer_external_id,
        "budget_cents": int(budget[0]),
        "actual_cents": int(actual),
        "estimated_cents": int(estimated),
        "total_cents": total,
        "utilization_pct": percentage,
        "level": level,
    }
