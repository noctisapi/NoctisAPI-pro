from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from control_center.customers import CustomerNotFound, create_customer, get_customer, list_customers, update_customer


def _connection(path: Path) -> sqlite3.Connection:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_02_control_center_customers")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def test_customer_crud_and_audit_are_local(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        customer_id = create_customer(
            conn,
            external_id="cus_a",
            legal_name="Acme A",
            actor_ref="operator-1",
            billing_ref="billing-a",
            notes="non-sensitive note",
        )
        updated = update_customer(conn, customer_id, actor_ref="operator-1", notes="updated")
        assert updated["legal_name"] == "Acme A"
        assert len(list_customers(conn)) == 1
        audit = conn.execute("SELECT * FROM cc_audit_log ORDER BY id").fetchall()
        assert len(audit) == 2
        assert "billing-a" not in audit[0]["details_json"]
    finally:
        conn.close()


def test_customer_scope_prevents_cross_customer_reads(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        first = create_customer(conn, external_id="cus_a", legal_name="Acme A", actor_ref="operator-1")
        create_customer(conn, external_id="cus_b", legal_name="Acme B", actor_ref="operator-1")
        assert [row["external_id"] for row in list_customers(conn, customer_scope=("cus_a",))] == ["cus_a"]
        with pytest.raises(CustomerNotFound):
            get_customer(conn, first + 1, customer_scope=("cus_a",))
    finally:
        conn.close()
