from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from control_center.customers import create_customer
from control_center.operations import (
    OperationValidationError,
    confirmation_phrase,
    preflight,
    result_projection,
    validate_confirmation,
)


def _connection(path: Path) -> sqlite3.Connection:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_02_control_center_customers")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    customer_id = create_customer(conn, external_id="cus_a", legal_name="Acme", actor_ref="operator-1")
    conn.execute(
        "INSERT INTO cc_deployments(customer_id, external_id, tenant_id, provider, region, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (customer_id, "dep_a", "tenant_a", "hetzner", "fsn1", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
    )
    conn.commit()
    return conn


def test_preflight_and_double_confirmation_for_teardown(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        result = preflight(conn, operation="teardown", deployment_id="dep_a")
        assert result.ok is True
        assert result.warnings
        with pytest.raises(OperationValidationError):
            validate_confirmation(operation="teardown", deployment_id="dep_a", first=True, second_phrase=None)
        validate_confirmation(
            operation="teardown",
            deployment_id="dep_a",
            first=True,
            second_phrase=confirmation_phrase("teardown", "dep_a"),
        )
    finally:
        conn.close()


def test_failed_job_projects_as_error_not_success() -> None:
    row = {"state": "failed", "error_code": "handler_failed"}
    projection = result_projection(row)  # type: ignore[arg-type]
    assert projection == {"state": "failed", "display": "error", "error_code": "handler_failed"}
