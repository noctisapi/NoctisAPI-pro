from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from control_center.costs import budget_alert, record_cost
from control_center.customers import create_customer
from control_center.subscriptions import SensitiveBillingDataError, record_billing_event, subscription_summary


def _connection(path: Path) -> sqlite3.Connection:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_03_control_center_billing_costs")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _seed(conn: sqlite3.Connection) -> tuple[int, str]:
    customer_id = create_customer(conn, external_id="cus_a", legal_name="Acme", actor_ref="operator-1")
    conn.execute(
        "INSERT INTO cc_subscriptions(customer_id, external_id, plan_code, commercial_state, mode, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (customer_id, "sub_a", "pro", "active", "managed", "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"),
    )
    conn.execute(
        "INSERT INTO cc_cost_budgets(customer_id, period_start, period_end, budget_cents, created_at) VALUES (?, ?, ?, ?, ?)",
        (customer_id, "2026-11-01", "2026-11-30", 1000, "2026-11-01T00:00:00Z"),
    )
    conn.commit()
    return customer_id, "sub_a"


def test_subscription_view_is_reconciled_without_card_data(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        _, subscription = _seed(conn)
        event_id = record_billing_event(
            conn,
            subscription_external_id=subscription,
            external_event_id="evt_1",
            provider="test-billing",
            event_type="invoice.paid",
            applied_state="active",
            payload={"invoice_ref": "inv_1"},
        )
        assert event_id == 1
        assert record_billing_event(
            conn,
            subscription_external_id=subscription,
            external_event_id="evt_1",
            provider="test-billing",
            event_type="invoice.paid",
            applied_state="active",
            payload={"invoice_ref": "inv_1"},
        ) == event_id
        summary = subscription_summary(conn)[0]
        assert summary["commercial_state"] == "active"
        assert summary["failed_reconciliation_count"] == 0
        with pytest.raises(SensitiveBillingDataError):
            record_billing_event(
                conn,
                subscription_external_id=subscription,
                external_event_id="evt_2",
                provider="test-billing",
                event_type="card.updated",
                applied_state=None,
                payload={"card_number": "4111111111111111"},
            )
    finally:
        conn.close()


def test_cost_alert_distinguishes_actual_and_estimated(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        customer_id, _ = _seed(conn)
        conn.execute(
            "INSERT INTO cc_deployments(customer_id, external_id, tenant_id, provider, region, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (customer_id, "dep_a", "tenant_a", "hetzner", "fsn1", "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"),
        )
        conn.commit()
        record_cost(conn, deployment_id="dep_a", provider="hetzner", period_start="2026-11-01", period_end="2026-11-30", amount_cents=600, currency="EUR", source="invoiced")
        record_cost(conn, deployment_id="dep_a", provider="backup", period_start="2026-11-01", period_end="2026-11-30", amount_cents=500, currency="EUR", source="estimated")
        alert = budget_alert(conn, customer_external_id="cus_a", period_start="2026-11-01", period_end="2026-11-30")
        assert alert["actual_cents"] == 600
        assert alert["estimated_cents"] == 500
        assert alert["level"] == "critical"
    finally:
        conn.close()
