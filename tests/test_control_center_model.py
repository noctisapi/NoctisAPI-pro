from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from control_center import CONTROL_CENTER_TABLES, ControlCenterInvariantError, validate_job_request


def _upgrade_to_control_center(path: Path) -> sqlite3.Connection:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_01_control_center")
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def test_control_center_migration_isolated_from_attack_and_panel_data(tmp_path: Path) -> None:
    conn = _upgrade_to_control_center(tmp_path / "control-center.db")
    try:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert set(CONTROL_CENTER_TABLES).issubset(tables)
        assert not {"attacks", "attack_events", "panel_sessions"}.intersection(
            set(CONTROL_CENTER_TABLES)
        )

        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(cc_audit_log)")
        }
        assert "details_json" in columns
        assert "password_hash" not in columns
    finally:
        conn.close()


def test_control_center_constraints_protect_customer_deployment_relationship(tmp_path: Path) -> None:
    conn = _upgrade_to_control_center(tmp_path / "control-center.db")
    try:
        conn.execute(
            "INSERT INTO cc_customers "
            "(external_id, legal_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("cus_1", "Example", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
        )
        customer_id = conn.execute("SELECT id FROM cc_customers").fetchone()[0]
        conn.execute(
            "INSERT INTO cc_deployments "
            "(customer_id, external_id, tenant_id, provider, region, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (customer_id, "dep_1", "tenant_1", "hetzner", "fsn1", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO cc_deployments "
                "(customer_id, external_id, tenant_id, provider, region, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (customer_id, "dep_2", "tenant_1", "hetzner", "nbg1", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
            )
    finally:
        conn.close()


def test_job_contract_allows_only_typed_operations() -> None:
    request = validate_job_request(
        {
            "job_type": "status",
            "deployment_id": "dep_1",
            "parameters": {"refresh": True},
        }
    )
    assert request["job_type"] == "status"

    with pytest.raises(ControlCenterInvariantError):
        validate_job_request(
            {"job_type": "shell", "deployment_id": "dep_1", "parameters": {"command": "whoami"}}
        )
