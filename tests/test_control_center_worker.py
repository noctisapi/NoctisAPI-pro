from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from control_center.adapters import AdapterRegistry, AdapterUnavailableError
from control_center.customers import create_customer
from control_center.jobs import create_job
from control_center.ports import DeploymentTarget, ProviderObservation
from control_center.worker import ReadOnlyJobError, ReadOnlyReconciliationWorker


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


class _Adapter:
    def observe(self, target: DeploymentTarget) -> ProviderObservation:
        return ProviderObservation(target.deployment_id, target.provider, target.region, "active", "2026-11-07T12:00:00Z")

    def execute(self, target: DeploymentTarget, operation: str, parameters: dict[str, object]):  # pragma: no cover
        raise AssertionError("read-only worker must never execute provider mutations")


def test_registry_fails_closed_for_unconfigured_provider() -> None:
    registry = AdapterRegistry({" Hetzner ": _Adapter()})
    assert registry.providers() == ("hetzner",)
    try:
        registry.get("cloudflare")
    except AdapterUnavailableError:
        pass
    else:  # pragma: no cover
        raise AssertionError("missing provider must fail closed")


def test_worker_reconciles_without_deploying(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        deployment = _deployment(conn)
        job_id = create_job(conn, deployment_id=deployment, job_type="reconcile", idempotency_key="reconcile-1", requested_by="operator-1")
        observation = ReadOnlyReconciliationWorker(conn, AdapterRegistry({"hetzner": _Adapter()})).run_job(job_id)
        assert observation is not None
        assert observation.state == "active"
        assert conn.execute("SELECT state FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()[0] == "succeeded"
        row = conn.execute("SELECT state, last_seen_at FROM cc_deployments WHERE external_id = ?", (deployment,)).fetchone()
        assert tuple(row) == ("active", "2026-11-07T12:00:00Z")
    finally:
        conn.close()


def test_worker_rejects_mutating_jobs_and_records_failure(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        deployment = _deployment(conn)
        job_id = create_job(conn, deployment_id=deployment, job_type="deploy", idempotency_key="deploy-1", requested_by="operator-1", confirmation=True)
        try:
            ReadOnlyReconciliationWorker(conn, AdapterRegistry({"hetzner": _Adapter()})).run_job(job_id)
        except ReadOnlyJobError:
            pass
        else:  # pragma: no cover
            raise AssertionError("mutating jobs must not run in the read-only worker")
        row = conn.execute("SELECT state, error_code FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()
        assert tuple(row) == ("failed", "read_only_worker")
    finally:
        conn.close()
