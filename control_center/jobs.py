"""Safe, typed Control Center job queue.

This is intentionally a local queue contract.  A deployed worker can claim a
job later, but it receives an allow-listed action and structured parameters,
never an HTTP-provided shell command.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from .model import validate_job_request

ACTIVE_STATES = ("queued", "running")
_READ_ONLY_JOBS = frozenset(("status", "verify"))


class JobConflictError(RuntimeError):
    pass


class JobIdempotencyError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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
) -> int:
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


def claim_job(conn: sqlite3.Connection, job_id: int) -> sqlite3.Row:
    """Atomically transition a queued job to running."""

    conn.row_factory = sqlite3.Row
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        conn.rollback()
        raise LookupError(job_id)
    if row["state"] != "queued":
        conn.rollback()
        raise JobConflictError(f"job {job_id} is not queued")
    conn.execute(
        "UPDATE cc_jobs SET state = 'running', started_at = ?, progress = 0 WHERE id = ?",
        (_now(), job_id),
    )
    conn.commit()
    return conn.execute("SELECT * FROM cc_jobs WHERE id = ?", (job_id,)).fetchone()


def finish_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    success: bool,
    error_code: str | None = None,
    error_message: str | None = None,
) -> None:
    state = "succeeded" if success else "failed"
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
        finish_job(conn, job_id, success=False, error_code="handler_unavailable", error_message="No handler registered")
        return None
    try:
        result = handler(json.loads(row["parameters_json"]))
    except Exception as exc:  # worker boundary: record failure, never success
        finish_job(conn, job_id, success=False, error_code="handler_failed", error_message=str(exc)[:500])
        return None
    finish_job(conn, job_id, success=True)
    return result
