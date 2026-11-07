"""Local release-flow contract test; it deliberately does not provision infra."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from control_center.adapters import AdapterRegistry
from control_center.customers import create_customer
from control_center.jobs import create_job
from control_center.ports import DeploymentTarget, ProviderObservation
from control_center.repository import SQLiteControlCenterReadRepository
from control_center.subscriptions import record_billing_event
from control_center.worker import ReadOnlyReconciliationWorker


class _ReleaseTestAdapter:
    def observe(self, target: DeploymentTarget) -> ProviderObservation:
        return ProviderObservation(
            deployment_id=target.deployment_id,
            provider=target.provider,
            region=target.region,
            state="active",
            observed_at="2026-11-07T12:00:00Z",
        )

    def execute(self, target: DeploymentTarget, operation: str, parameters: dict[str, object]):  # pragma: no cover
        raise AssertionError("release contract test must not provision infrastructure")


def test_local_contract_flow_customer_to_observed_deployment(tmp_path: Path) -> None:
    db_path = tmp_path / "control-center.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{db_path.as_posix()}")
    command.upgrade(config, "20261107_04_control_center_worker_leases")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        customer_id = create_customer(conn, external_id="cus_release", legal_name="Release Acme", actor_ref="operator-1")
        conn.execute(
            """
            INSERT INTO cc_subscriptions
              (customer_id, external_id, plan_code, commercial_state, mode, created_at, updated_at)
            VALUES (?, ?, ?, 'active', 'managed', ?, ?)
            """,
            (customer_id, "sub_release", "managed-pro", "2026-11-07T12:00:00Z", "2026-11-07T12:00:00Z"),
        )
        subscription_id = conn.execute("SELECT id FROM cc_subscriptions WHERE external_id = 'sub_release'").fetchone()[0]
        conn.execute(
            """
            INSERT INTO cc_deployments
              (customer_id, subscription_id, external_id, tenant_id, provider, region, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (customer_id, subscription_id, "dep_release", "tenant_release", "hetzner", "fsn1", "2026-11-07T12:00:00Z", "2026-11-07T12:00:00Z"),
        )
        conn.commit()

        record_billing_event(
            conn,
            subscription_external_id="sub_release",
            external_event_id="evt_release_1",
            provider="test-billing",
            event_type="subscription.active",
            applied_state="active",
            payload={"plan": "managed-pro"},
        )
        job_id = create_job(
            conn,
            deployment_id="dep_release",
            job_type="reconcile",
            idempotency_key="release-reconcile-1",
            requested_by="operator-1",
        )
        observation = ReadOnlyReconciliationWorker(
            conn,
            AdapterRegistry({"hetzner": _ReleaseTestAdapter()}),
        ).run_job(job_id)

        repository = SQLiteControlCenterReadRepository(conn)
        assert repository.customers()[0]["external_id"] == "cus_release"
        assert repository.subscriptions()[0]["commercial_state"] == "active"
        assert repository.inventory()[0]["state"] == observation.state == "active"
        assert conn.execute("SELECT state FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()[0] == "succeeded"
    finally:
        conn.close()
