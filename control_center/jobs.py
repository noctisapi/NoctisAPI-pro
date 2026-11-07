"""Safe, typed Control Center job queue.

This is intentionally a local queue contract.  A deployed worker can claim a
job later, but it receives an allow-listed action and structured parameters,
never an HTTP-provided shell command.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .model import validate_job_request

ACTIVE_STATES = ("queued", "running")
_READ_ONLY_JOBS = frozenset(("status", "verify"))


class JobConflictError(RuntimeError):
    pass


class JobIdempotencyError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _lease_columns_available(conn: sqlite3.Connection) -> bool:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(cc_jobs)").fetchall()}
    return {"attempt_count", "max_attempts", "lease_token", "lease_expires_at", "heartbeat_at"}.issubset(columns)


def _lease_deadline(seconds: int) -> str:
    if seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")


def _row_lease_token(row: sqlite3.Row) -> str | None:
    return row["lease_token"] if "lease_token" in row.keys() else None


def _incompatible(existing_type: str, requested_type: str) -> bool:
    return not (existing_type in _READ_ONLY_JOBS and requested_type in _READ_ONLY_JOBS)


def create_job(
    conn: sqlite3.Connection,
    *,
    deployment_id: str,
    job_type: str,
    idempotency_key: str,
    requested_by: str,
    parameters: Mapping[str, Any] | None = None,
    confirmation: bool = False,
    max_attempts: int = 3,
) -> int:
    if isinstance(max_attempts, bool) or not 1 <= max_attempts <= 10:
        raise ValueError("max_attempts must be an integer between 1 and 10")
    request = validate_job_request(
        {
            "job_type": job_type,
            "deployment_id": deployment_id,
            "parameters": parameters or {},
            "confirmation": confirmation,
        }
    )
    existing = conn.execute(
        "SELECT id, job_type, parameters_json FROM cc_jobs WHERE idempotency_key = ?",
        (idempotency_key,),
    ).fetchone()
    encoded_parameters = json.dumps(request["parameters"], sort_keys=True)
    if existing:
        if existing[1] != job_type or existing[2] != encoded_parameters:
            raise JobIdempotencyError(idempotency_key)
        return int(existing[0])

    deployment = conn.execute(
        "SELECT id FROM cc_deployments WHERE external_id = ?",
        (deployment_id,),
    ).fetchone()
    if deployment is None:
        raise LookupError(deployment_id)

    active = conn.execute(
        """
        SELECT job_type FROM cc_jobs
         WHERE deployment_id = ? AND state IN ('queued', 'running')
        """,
        (deployment[0],),
    ).fetchall()
    if any(_incompatible(row[0], job_type) for row in active):
        raise JobConflictError(f"active job already locks deployment {deployment_id}")

    now = _now()
    if _lease_columns_available(conn):
        cursor = conn.execute(
            """
            INSERT INTO cc_jobs(
                deployment_id, job_type, state, idempotency_key, requested_by,
                parameters_json, max_attempts, created_at
            ) VALUES (?, ?, 'queued', ?, ?, ?, ?, ?)
            """,
            (deployment[0], job_type, idempotency_key, requested_by, encoded_parameters, max_attempts, now),
        )
    else:
        cursor = conn.execute(
            """
            INSERT INTO cc_jobs(
                deployment_id, job_type, state, idempotency_key, requested_by,
                parameters_json, created_at
            ) VALUES (?, ?, 'queued', ?, ?, ?, ?)
            """,
            (deployment[0], job_type, idempotency_key, requested_by, encoded_parameters, now),
        )
    conn.commit()
    return int(cursor.lastrowid)


def claim_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    lease_seconds: int = 60,
    lease_owner: str | None = None,
) -> sqlite3.Row:
    """Atomically claim a job, reclaiming an expired lease when possible."""

    conn.row_factory = sqlite3.Row
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        conn.rollback()
        raise LookupError(job_id)
    if not _lease_columns_available(conn):
        if row["state"] != "queued":
            conn.rollback()
            raise JobConflictError(f"job {job_id} is not queued")
        conn.execute(
            "UPDATE cc_jobs SET state = 'running', started_at = ?, progress = 0 WHERE id = ?",
            (_now(), job_id),
        )
    else:
        now = _now()
        if row["state"] == "running" and row["lease_expires_at"] and row["lease_expires_at"] > now:
            conn.rollback()
            raise JobConflictError(f"job {job_id} has an active lease")
        if row["state"] not in ("queued", "running"):
            conn.rollback()
            raise JobConflictError(f"job {job_id} is not claimable")
        if row["state"] == "running" and int(row["attempt_count"] or 0) >= int(row["max_attempts"]):
            conn.execute(
                """
                UPDATE cc_jobs
                   SET state = 'failed', error_code = 'lease_exhausted',
                       error_message = 'job lease expired too many times', completed_at = ?,
                       lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
                 WHERE id = ? AND state = 'running'
                """,
                (now, job_id),
            )
            conn.commit()
            raise JobConflictError(f"job {job_id} exhausted its lease retries")
        token = f"{lease_owner}:{uuid4().hex}" if lease_owner else uuid4().hex
        conn.execute(
            """
            UPDATE cc_jobs
               SET state = 'running', started_at = ?, progress = 0,
                   attempt_count = attempt_count + 1, lease_token = ?,
                   lease_expires_at = ?, heartbeat_at = ?
             WHERE id = ?
            """,
            (now, token, _lease_deadline(lease_seconds), now, job_id),
        )
    conn.commit()
    return conn.execute("SELECT * FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()


def heartbeat_job(conn: sqlite3.Connection, job_id: int, *, lease_token: str, lease_seconds: int = 60) -> bool:
    """Extend a live lease only when the caller still owns its token."""

    if not _lease_columns_available(conn):
        return False
    now = _now()
    result = conn.execute(
        """
        UPDATE cc_jobs
           SET lease_expires_at = ?, heartbeat_at = ?
         WHERE id = ? AND state = 'running' AND lease_token = ?
        """,
        (_lease_deadline(lease_seconds), now, job_id, lease_token),
    )
    conn.commit()
    return result.rowcount == 1


def retry_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    lease_token: str | None,
    error_code: str,
    error_message: str,
) -> bool:
    """Return a failed attempt to the queue while its retry budget remains."""

    if not _lease_columns_available(conn):
        return False
    result = conn.execute(
        """
        UPDATE cc_jobs
           SET state = 'queued', progress = 0, error_code = ?, error_message = ?,
               completed_at = NULL, lease_token = NULL, lease_expires_at = NULL,
               heartbeat_at = NULL
         WHERE id = ? AND state = 'running' AND lease_token = ?
           AND attempt_count < max_attempts
        """,
        (error_code, error_message[:500], job_id, lease_token),
    )
    conn.commit()
    return result.rowcount == 1


def finish_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    success: bool,
    error_code: str | None = None,
    error_message: str | None = None,
    lease_token: str | None = None,
) -> None:
    state = "succeeded" if success else "failed"
    if _lease_columns_available(conn):
        conn.execute(
            """
            UPDATE cc_jobs
               SET state = ?, progress = ?, error_code = ?, error_message = ?, completed_at = ?,
                   lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
             WHERE id = ? AND state = 'running'
               AND (? IS NULL OR lease_token = ?)
            """,
            (state, 100 if success else 0, error_code, error_message, _now(), job_id, lease_token, lease_token),
        )
    else:
        conn.execute(
            """
            UPDATE cc_jobs
               SET state = ?, progress = ?, error_code = ?, error_message = ?, completed_at = ?
             WHERE id = ? AND state = 'running'
            """,
            (state, 100 if success else 0, error_code, error_message, _now(), job_id),
        )
    conn.commit()


def run_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    handlers: Mapping[str, Callable[[dict[str, Any]], object]],
) -> object | None:
    """Run one allow-listed handler and persist a truthful final state."""

    row = claim_job(conn, job_id)
    handler = handlers.get(row["job_type"])
    if handler is None:
        finish_job(conn, job_id, success=False, error_code="handler_unavailable", error_message="No handler registered", lease_token=_row_lease_token(row))
        return None
    try:
        result = handler(json.loads(row["parameters_json"]))
    except Exception as exc:  # worker boundary: record failure, never success
        finish_job(conn, job_id, success=False, error_code="handler_failed", error_message=str(exc)[:500], lease_token=_row_lease_token(row))
        return None
    finish_job(conn, job_id, success=True, lease_token=_row_lease_token(row))
    return result
