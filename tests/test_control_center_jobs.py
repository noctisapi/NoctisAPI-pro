from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from control_center.customers import create_customer
from control_center.jobs import JobConflictError, JobIdempotencyError, create_job, run_job


def _connection(path: Path) -> sqlite3.Connection:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_02_control_center_customers")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _deployment(conn: sqlite3.Connection) -> str:
    customer_id = create_customer(conn, external_id="cus_a", legal_name="Acme", actor_ref="operator-1")
    conn.execute(
        """
        INSERT INTO cc_deployments
          (customer_id, external_id, tenant_id, provider, region, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (customer_id, "dep_a", "tenant_a", "hetzner", "fsn1", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
    )
    conn.commit()
    return "dep_a"


def test_jobs_are_typed_idempotent_and_locked_per_deployment(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        deployment = _deployment(conn)
        first = create_job(
            conn,
            deployment_id=deployment,
            job_type="status",
            idempotency_key="request-1",
            requested_by="operator-1",
        )
        assert create_job(
            conn,
            deployment_id=deployment,
            job_type="status",
            idempotency_key="request-1",
            requested_by="operator-1",
        ) == first
        with pytest.raises(JobIdempotencyError):
            create_job(
                conn,
                deployment_id=deployment,
                job_type="verify",
                idempotency_key="request-1",
                requested_by="operator-1",
            )

        with pytest.raises(JobConflictError):
            create_job(
                conn,
                deployment_id=deployment,
                job_type="upgrade",
                idempotency_key="request-2",
                requested_by="operator-1",
            )
        with pytest.raises(Exception):
            create_job(
                conn,
                deployment_id=deployment,
                job_type="shell",
                idempotency_key="request-3",
                requested_by="operator-1",
                parameters={"command": "whoami"},
            )
    finally:
        conn.close()


def test_runner_records_success_and_failure_truthfully(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        deployment = _deployment(conn)
        success_id = create_job(
            conn,
            deployment_id=deployment,
            job_type="status",
            idempotency_key="request-success",
            requested_by="operator-1",
            parameters={"refresh": True},
        )
        assert run_job(conn, success_id, handlers={"status": lambda params: {"ok": params["refresh"]}}) == {"ok": True}
        assert conn.execute("SELECT state FROM cc_jobs WHERE id = ?", (success_id,)).fetchone()[0] == "succeeded"

        failure_id = create_job(
            conn,
            deployment_id=deployment,
            job_type="verify",
            idempotency_key="request-failure",
            requested_by="operator-1",
        )
        assert run_job(conn, failure_id, handlers={"verify": lambda params: (_ for _ in ()).throw(RuntimeError("provider unavailable"))}) is None
        row = conn.execute("SELECT state, error_code FROM cc_jobs WHERE id = ?", (failure_id,)).fetchone()
        assert tuple(row) == ("failed", "handler_failed")
    finally:
        conn.close()
