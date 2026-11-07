from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from control_center.customers import create_customer
from control_center.repository import SQLiteControlCenterReadRepository, open_sqlite_repository


def _db(path: Path) -> None:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_03_control_center_billing_costs")
    conn = sqlite3.connect(path)
    customer_id = create_customer(conn, external_id="cus_a", legal_name="Acme", actor_ref="operator-1")
    conn.execute(
        "INSERT INTO cc_deployments(customer_id, external_id, tenant_id, provider, region, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (customer_id, "dep_a", "tenant_a", "hetzner", "fsn1", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
    )
    conn.commit()
    conn.close()


def test_sqlite_repository_exposes_read_models(tmp_path: Path) -> None:
    path = tmp_path / "control-center.db"
    _db(path)
    with open_sqlite_repository(str(path)) as repository:
        assert repository.customers()[0]["external_id"] == "cus_a"
        assert repository.inventory()[0]["external_id"] == "dep_a"
        assert repository.subscriptions() == []


def test_repository_implementation_accepts_existing_connection(tmp_path: Path) -> None:
    path = tmp_path / "control-center.db"
    _db(path)
    conn = sqlite3.connect(path)
    try:
        repository = SQLiteControlCenterReadRepository(conn)
        assert repository.customers()[0]["legal_name"] == "Acme"
    finally:
        conn.close()
