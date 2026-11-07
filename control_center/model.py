"""Pure-Python Control Center data contracts.

This module deliberately contains no provider SDK, network client, or
database connection.  It is the local contract used by the migration, APIs,
and later job-runner work.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

MODEL_VERSION = 1

CONTROL_CENTER_TABLES = (
    "cc_customers",
    "cc_subscriptions",
    "cc_deployments",
    "cc_domains",
    "cc_jobs",
    "cc_versions",
    "cc_infra_costs",
    "cc_audit_log",
)

COMMERCIAL_STATES = ("pending", "active", "past_due", "suspended", "terminated")
DEPLOYMENT_STATES = (
    "pending",
    "provisioning",
    "active",
    "stale",
    "suspended",
    "terminated",
)
DOMAIN_KINDS = ("api", "console", "other")
JOB_STATES = ("queued", "running", "succeeded", "failed", "cancelled")
JOB_TYPES = (
    "deploy",
    "status",
    "verify",
    "upgrade",
    "backup",
    "suspend",
    "teardown",
    "reconcile",
)
AUDIT_ACTIONS = (
    "create",
    "update",
    "delete",
    "login",
    "job_requested",
    "job_completed",
    "job_failed",
    "plan_changed",
    "secret_rotated",
)


class ControlCenterInvariantError(ValueError):
    """Raised when a Control Center record violates a local invariant."""


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ControlCenterInvariantError(f"{key} must be a non-empty string")
    return value.strip()


def validate_job_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a typed job request before it reaches a queue or runner.

    Arbitrary shell commands are intentionally not part of this contract.
    Parameters are opaque JSON for now but must be a mapping and the action
    must be one of the bounded deployer operations.
    """

    job_type = _require_text(payload, "job_type")
    if job_type not in JOB_TYPES:
        raise ControlCenterInvariantError(f"unsupported job_type: {job_type}")

    deployment_id = _require_text(payload, "deployment_id")
    parameters = payload.get("parameters", {})
    if not isinstance(parameters, Mapping):
        raise ControlCenterInvariantError("parameters must be an object")

    confirmation = payload.get("confirmation", False)
    if not isinstance(confirmation, bool):
        raise ControlCenterInvariantError("confirmation must be boolean")

    return {
        "job_type": job_type,
        "deployment_id": deployment_id,
        "parameters": dict(parameters),
        "confirmation": confirmation,
    }
