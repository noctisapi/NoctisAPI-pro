"""Preflight and truthful result contracts for the Control Center UI."""

from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from collections.abc import Mapping

from .model import validate_job_request

DESTRUCTIVE_OPERATIONS = frozenset(("teardown",))


class OperationValidationError(ValueError):
    pass


@dataclass(frozen=True)
class PreflightResult:
    ok: bool
    operation: str
    deployment_id: str
    warnings: tuple[str, ...] = ()


def preflight(
    conn: sqlite3.Connection,
    *,
    operation: str,
    deployment_id: str,
    parameters: dict | None = None,
) -> PreflightResult:
    """Validate a UI operation without enqueueing or touching infrastructure."""

    validate_job_request(
        {
            "job_type": operation,
            "deployment_id": deployment_id,
            "parameters": parameters or {},
        }
    )
    if conn.execute("SELECT 1 FROM cc_deployments WHERE external_id = ?", (deployment_id,)).fetchone() is None:
        raise OperationValidationError(f"unknown deployment: {deployment_id}")
    warnings: list[str] = []
    if operation in DESTRUCTIVE_OPERATIONS:
        warnings.append("This operation is irreversible and requires two confirmations.")
    return PreflightResult(True, operation, deployment_id, tuple(warnings))


def confirmation_phrase(operation: str, deployment_id: str) -> str:
    if operation not in DESTRUCTIVE_OPERATIONS:
        raise OperationValidationError("confirmation phrase is only required for destructive operations")
    return f"CONFIRM {operation.upper()} {deployment_id}"


def validate_confirmation(
    *,
    operation: str,
    deployment_id: str,
    first: bool,
    second_phrase: str | None,
) -> None:
    if operation not in DESTRUCTIVE_OPERATIONS:
        return
    if not first or second_phrase != confirmation_phrase(operation, deployment_id):
        raise OperationValidationError("two explicit confirmations are required")


def result_projection(row: sqlite3.Row | tuple) -> dict[str, object]:
    """Project a job row so failed operations cannot be rendered as success."""

    if isinstance(row, Mapping) or isinstance(row, sqlite3.Row):
        state = row["state"]
        error_code = row["error_code"]
    else:
        state, error_code = row[0], row[1]
    if state == "succeeded":
        display = "success"
    elif state == "failed":
        display = "error"
    else:
        display = "pending"
    return {"state": state, "display": display, "error_code": error_code}
