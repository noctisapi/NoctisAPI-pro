from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from control_center.adapters import AdapterRegistry, AdapterUnavailableError
from control_center.customers import create_customer
from control_center.jobs import claim_job, create_job, finish_job
from control_center.ports import DeploymentTarget, ProviderObservation
from control_center.worker import ReadOnlyJobError, ReadOnlyReconciliationWorker


def _connection(path: Path) -> sqlite3.Connection:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261107_05_control_center_provider_refs")
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


class _FlakyAdapter(_Adapter):
    def __init__(self) -> None:
        self.attempts = 0

    def observe(self, target: DeploymentTarget) -> ProviderObservation:
        self.attempts += 1
        if self.attempts == 1:
            raise RuntimeError("temporary provider error")
        return super().observe(target)


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


def test_worker_run_next_ignores_mutating_jobs_and_processes_oldest_read_only_job(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        deployment = _deployment(conn)
        second_customer_id = create_customer(conn, external_id="cus_b", legal_name="Beta", actor_ref="operator-1")
        conn.execute(
            """
            INSERT INTO cc_deployments
              (customer_id, external_id, tenant_id, provider, region, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (second_customer_id, "dep_b", "tenant_b", "hetzner", "fsn1", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
        )
        conn.commit()
        create_job(conn, deployment_id=deployment, job_type="deploy", idempotency_key="deploy-pending", requested_by="operator-1", confirmation=True)
        status_id = create_job(conn, deployment_id="dep_b", job_type="status", idempotency_key="status-pending", requested_by="operator-1")
        worker = ReadOnlyReconciliationWorker(conn, AdapterRegistry({"hetzner": _Adapter()}))

        assert worker.run_next() is not None
        assert conn.execute("SELECT state FROM cc_jobs WHERE id = ?", (status_id,)).fetchone()[0] == "succeeded"
        assert conn.execute("SELECT state FROM cc_jobs WHERE id != ?", (status_id,)).fetchone()[0] == "queued"
        assert worker.run_next() is None
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


def test_worker_retries_with_bounded_attempts_and_supports_heartbeat(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        deployment = _deployment(conn)
        job_id = create_job(
            conn,
            deployment_id=deployment,
            job_type="status",
            idempotency_key="retry-1",
            requested_by="operator-1",
            max_attempts=2,
        )
        adapter = _FlakyAdapter()
        worker = ReadOnlyReconciliationWorker(conn, AdapterRegistry({"hetzner": adapter}), lease_seconds=30)

        assert worker.run_next() is None
        first = conn.execute("SELECT state, attempt_count, error_code FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()
        assert tuple(first) == ("queued", 1, "observation_retry")
        assert worker.run_next() is not None
        second = conn.execute("SELECT state, attempt_count FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()
        assert tuple(second) == ("succeeded", 2)

        heartbeat_id = create_job(
            conn,
            deployment_id=deployment,
            job_type="verify",
            idempotency_key="heartbeat-1",
            requested_by="operator-1",
        )
        claimed = claim_job(conn, heartbeat_id, lease_seconds=30, lease_owner="external-worker")
        assert claimed["lease_token"].startswith("external-worker:")
        assert worker.heartbeat(heartbeat_id, claimed["lease_token"])
        finish_job(conn, heartbeat_id, success=True, lease_token=claimed["lease_token"])
        assert worker.run_forever(poll_interval=0, max_ticks=2) == 2
    finally:
        conn.close()


def test_worker_continues_when_an_expired_lease_has_exhausted_attempts(tmp_path: Path) -> None:
    conn = _connection(tmp_path / "control-center.db")
    try:
        deployment = _deployment(conn)
        job_id = create_job(
            conn,
            deployment_id=deployment,
            job_type="status",
            idempotency_key="lease-exhausted-1",
            requested_by="operator-1",
            max_attempts=1,
        )
        claimed = claim_job(conn, job_id, lease_seconds=30, lease_owner="dead-worker")
        conn.execute(
            "UPDATE cc_jobs SET lease_expires_at = '2000-01-01T00:00:00Z' WHERE id = ?",
            (job_id,),
        )
        conn.commit()

        worker = ReadOnlyReconciliationWorker(conn, AdapterRegistry({"hetzner": _Adapter()}))
        assert worker.run_next() is None
        row = conn.execute("SELECT state, error_code FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()
        assert tuple(row) == ("failed", "lease_exhausted")
        assert claimed["lease_token"]
    finally:
        conn.close()
