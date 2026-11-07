"""Read-only reconciliation worker for the first Control Center iteration."""

from __future__ import annotations

import sqlite3

from .adapters import AdapterRegistry
from .inventory import record_observation
from .jobs import claim_job, finish_job
from .model import DEPLOYMENT_STATES
from .ports import DeploymentTarget, ProviderObservation

READ_ONLY_JOB_TYPES = frozenset(("status", "verify", "reconcile"))


class ReadOnlyJobError(ValueError):
    """Raised when a mutating job is sent to this safe worker."""


class ReadOnlyReconciliationWorker:
    """Execute one provider observation job and persist its result.

    This worker never calls ``execute`` on an adapter. Provider-specific
    deployment or infrastructure changes belong to a later, separately
    authorized worker.
    """

    def __init__(self, conn: sqlite3.Connection, adapters: AdapterRegistry) -> None:
        self._conn = conn
        self._adapters = adapters

    def run_next(self) -> ProviderObservation | None:
        """Run the oldest queued read-only job, or do nothing if none exists.

        A process supervisor can call this method on its own schedule. It is
        intentionally a single tick: lifecycle, backoff, telemetry and
        process supervision belong outside this provider-safe boundary.
        """

        row = self._conn.execute(
            """
            SELECT id
              FROM cc_jobs
             WHERE state = 'queued' AND job_type IN ('status', 'verify', 'reconcile')
             ORDER BY id
             LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        return self.run_job(int(row[0]))

    def run_job(self, job_id: int) -> ProviderObservation | None:
        row = claim_job(self._conn, job_id)
        if row["job_type"] not in READ_ONLY_JOB_TYPES:
            finish_job(
                self._conn,
                job_id,
                success=False,
                error_code="read_only_worker",
                error_message="job type is not enabled in the read-only worker",
            )
            raise ReadOnlyJobError(row["job_type"])

        try:
            deployment = self._conn.execute(
                "SELECT external_id, tenant_id, provider, region FROM cc_deployments WHERE id = ?",
                (row["deployment_id"],),
            ).fetchone()
            if deployment is None:
                raise LookupError(row["deployment_id"])

            target = DeploymentTarget(
                deployment_id=deployment[0],
                tenant_id=deployment[1],
                provider=deployment[2],
                region=deployment[3],
            )
            observation = self._adapters.get(target.provider).observe(target)
            self._validate_observation(observation, target)
            record_observation(
                self._conn,
                deployment_external_id=observation.deployment_id,
                provider=observation.provider,
                region=observation.region,
                state=observation.state,
                observed_at=observation.observed_at,
            )
        except Exception as exc:
            finish_job(
                self._conn,
                job_id,
                success=False,
                error_code="observation_failed",
                error_message=str(exc)[:500],
            )
            return None

        finish_job(self._conn, job_id, success=True)
        return observation

    @staticmethod
    def _validate_observation(observation: ProviderObservation, target: DeploymentTarget) -> None:
        if not isinstance(observation, ProviderObservation):
            raise TypeError("adapter must return ProviderObservation")
        if observation.deployment_id != target.deployment_id:
            raise ValueError("adapter observation deployment mismatch")
        if observation.provider != target.provider:
            raise ValueError("adapter observation provider mismatch")
        if observation.state not in DEPLOYMENT_STATES:
            raise ValueError(f"unsupported observed deployment state: {observation.state}")
        if not observation.observed_at.strip():
            raise ValueError("observation timestamp is required")
