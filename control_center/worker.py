"""Read-only reconciliation worker for the first Control Center iteration."""

from __future__ import annotations

import sqlite3
from threading import Event

from .adapters import AdapterRegistry
from .inventory import record_observation
from .jobs import JobConflictError, _lease_columns_available, claim_job, finish_job, heartbeat_job, retry_job
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

    def __init__(self, conn: sqlite3.Connection, adapters: AdapterRegistry, *, worker_id: str = "control-center-worker", lease_seconds: int = 60) -> None:
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._conn = conn
        self._adapters = adapters
        self._worker_id = worker_id
        self._lease_seconds = lease_seconds

    def run_next(self) -> ProviderObservation | None:
        """Run the oldest queued read-only job, or do nothing if none exists.

        A process supervisor can call this method on its own schedule. It is
        intentionally a single tick: lifecycle, backoff, telemetry and
        process supervision belong outside this provider-safe boundary.
        """

        if _lease_columns_available(self._conn):
            row = self._conn.execute(
                """
                SELECT id
                  FROM cc_jobs
                 WHERE job_type IN ('status', 'verify', 'reconcile')
                   AND (state = 'queued' OR
                        (state = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?))
                 ORDER BY id
                 LIMIT 1
                """,
                (self._now(),),
            ).fetchone()
        else:
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
        try:
            return self.run_job(int(row[0]))
        except JobConflictError:
            # Another worker may have won the claim, or the lease budget may
            # have been exhausted and marked terminal by claim_job.
            return None

    def run_forever(
        self,
        *,
        stop_event: Event | None = None,
        poll_interval: float = 1.0,
        max_ticks: int | None = None,
    ) -> int:
        """Run polling ticks until stopped; useful behind a process supervisor."""

        if poll_interval < 0:
            raise ValueError("poll_interval cannot be negative")
        if max_ticks is not None and max_ticks < 0:
            raise ValueError("max_ticks cannot be negative")
        stopper = stop_event or Event()
        ticks = 0
        while not stopper.is_set() and (max_ticks is None or ticks < max_ticks):
            self.run_next()
            ticks += 1
            if not stopper.is_set() and poll_interval:
                stopper.wait(poll_interval)
        return ticks

    def heartbeat(self, job_id: int, lease_token: str) -> bool:
        """Extend a job lease without exposing provider-specific behavior."""

        return heartbeat_job(self._conn, job_id, lease_token=lease_token, lease_seconds=self._lease_seconds)

    def run_job(self, job_id: int) -> ProviderObservation | None:
        row = claim_job(
            self._conn,
            job_id,
            lease_seconds=self._lease_seconds,
            lease_owner=self._worker_id,
        )
        if row["job_type"] not in READ_ONLY_JOB_TYPES:
            finish_job(
                self._conn,
                job_id,
                success=False,
                error_code="read_only_worker",
                error_message="job type is not enabled in the read-only worker",
                lease_token=row["lease_token"] if "lease_token" in row.keys() else None,
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
            lease_token = row["lease_token"] if "lease_token" in row.keys() else None
            if not retry_job(
                self._conn,
                job_id,
                lease_token=lease_token,
                error_code="observation_retry",
                error_message=str(exc),
            ):
                finish_job(
                    self._conn,
                    job_id,
                    success=False,
                    error_code="observation_failed",
                    error_message=str(exc)[:500],
                    lease_token=lease_token,
                )
            return None

        finish_job(
            self._conn,
            job_id,
            success=True,
            lease_token=row["lease_token"] if "lease_token" in row.keys() else None,
        )
        return observation

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

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
