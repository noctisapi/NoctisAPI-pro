from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config

from control_center.customers import create_customer
from control_center.inventory import list_inventory, record_observation


def _connection(path: Path) -> sqlite3.Connection:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_02_control_center_customers")
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _seed(conn: sqlite3.Connection, customer_external_id: str, deployment_external_id: str) -> None:
    customer_id = create_customer(
        conn,
        external_id=customer_external_id,
        legal_name=customer_external_id,
        actor_ref="operator-1",
    )
    conn.execute(
        """
        INSERT INTO cc_deployments
          (customer_id, external_id, tenant_id, provider, region, state, last_seen_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            customer_id,
            deployment_external_id,
            f"tenant-{deployment_external_id}",
            "hetzner",
            "fsn1",
            "active",
            "2026-11-06T11:55:00Z",
            "2026-11-06T11:00:00Z",
            "2026-11-06T11:55:00Z",
        ),
    )
    conn.commit()


def test_inventory_filters_scope_and_marks_stale_data(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        _seed(conn, "cus_a", "dep_a")
        _seed(conn, "cus_b", "dep_b")
        result = list_inventory(
            conn,
            customer_scope=("cus_a",),
            now=datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc),
            stale_after_seconds=120,
        )
        assert [item["external_id"] for item in result] == ["dep_a"]
        assert result[0]["stale"] is True
    finally:
        conn.close()


def test_observation_refreshes_inventory_state(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        _seed(conn, "cus_a", "dep_a")
        record_observation(
            conn,
            deployment_external_id="dep_a",
            provider="hetzner",
            region="nbg1",
            state="active",
            observed_at="2026-11-06T12:00:00Z",
        )
        item = list_inventory(
            conn,
            now=datetime(2026, 11, 6, 12, 1, tzinfo=timezone.utc),
            stale_after_seconds=120,
        )[0]
        assert item["region"] == "nbg1"
        assert item["stale"] is False
    finally:
        conn.close()
