#!/usr/bin/env python
"""
Deployment manifest schema, state machine, and validation (NOC-031).

This is the data contract between the internal admin panel, a future
CLI (NOC-035), and future automated provisioning (Noctis Deployer,
NOC-032/033/034) -- all three will read/write
`compose/secrets/deployment-manifest.json` and need to agree on its
shape without coordinating through code. `scripts/init_deployment.py`
(NOC-025) remains the only place that actually creates/writes the file
day-to-day; this module defines what "valid" means for it, and the
infra lifecycle state machine layered on top.

Schema v1 fields (each independently optional except `deployment_id`,
`created_at`, `schema_version` -- the file as a whole may still be
partially filled during early rollout):
  schema_version   int, this module's SCHEMA_VERSION.
  deployment_id    str, uuid4 hex. Generated once by init_deployment.py,
                   NEVER regenerated -- this is the stable id every
                   other system (CLI, Deployer, Control Center)
                   reconciles against. See "Sin secretos" below: this
                   is a random identifier, not a credential.
  created_at / updated_at   ISO8601 UTC timestamps.
  customer_id      str, operator-assigned. Empty for self-hosted.
  region           str, free-form (e.g. a cloud region code). Meaning
                   is Deployer-defined (NOC-032); this module only
                   carries the value.
  sizing           str, free-form tier label (e.g. "small"). Same.
  plan             str, free-form commercial plan label. NOT the same
                   state machine as NOC-043's billing status (pending/
                   active/past_due/suspended/terminated) -- that's a
                   separate, future concern; this is just a label.
  hp_public_host / hp_admin_host   str, the two configured domains.
  status / status_history   this module's DeploymentStatus state
                   machine -- INFRASTRUCTURE lifecycle (is it up,
                   degraded, being torn down), not billing status.
  app_image / previous_app_image / app_image_digest / upgrade_history
                   written by scripts/upgrade.py (NOC-029), unchanged here.

Sin secretos (acceptance criterion): validate_manifest() enforces this
mechanically, not just by convention -- it rejects any key whose name
contains one of app/structured_logging.py's own sensitive-substring
list (NOC-025), the same list that already redacts log output.
"""
from __future__ import annotations

import argparse
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
from app.structured_logging import _SENSITIVE_KEY_SUBSTRINGS  # noqa: E402

SCHEMA_VERSION = 1
_SUPPORTED_SCHEMA_VERSIONS = {1}

_DEFAULT_MANIFEST_PATH = _REPO_ROOT / "compose" / "secrets" / "deployment-manifest.json"

_STRING_FIELDS = (
    "customer_id", "region", "sizing", "plan", "hp_public_host", "hp_admin_host",
    "app_image", "previous_app_image", "app_image_digest",
)
_LIST_FIELDS = ("upgrade_history", "status_history")


class DeploymentStatus(str, Enum):
    """Infrastructure lifecycle -- distinct from NOC-043's future
    commercial/billing state machine (pending/active/past_due/
    suspended/terminated), which tracks payment status, not whether
    the VPS itself is up."""

    PROVISIONING = "provisioning"
    ACTIVE = "active"
    UPGRADING = "upgrading"
    DEGRADED = "degraded"
    SUSPENDED = "suspended"
    DECOMMISSIONING = "decommissioning"
    DECOMMISSIONED = "decommissioned"
    FAILED = "failed"


# Directed graph of allowed transitions. DECOMMISSIONED is terminal.
# A status transitioning to itself is always allowed (idempotency --
# re-running an operation that already reached its target status must
# not error) and is intentionally left out of this table; see
# validate_transition().
_VALID_TRANSITIONS: Dict[DeploymentStatus, Set[DeploymentStatus]] = {
    DeploymentStatus.PROVISIONING: {DeploymentStatus.ACTIVE, DeploymentStatus.FAILED},
    DeploymentStatus.ACTIVE: {
        DeploymentStatus.UPGRADING, DeploymentStatus.DEGRADED,
        DeploymentStatus.SUSPENDED, DeploymentStatus.DECOMMISSIONING,
    },
    DeploymentStatus.UPGRADING: {DeploymentStatus.ACTIVE, DeploymentStatus.DEGRADED, DeploymentStatus.FAILED},
    DeploymentStatus.DEGRADED: {
        DeploymentStatus.ACTIVE, DeploymentStatus.SUSPENDED, DeploymentStatus.DECOMMISSIONING,
    },
    DeploymentStatus.SUSPENDED: {DeploymentStatus.ACTIVE, DeploymentStatus.DECOMMISSIONING},
    DeploymentStatus.DECOMMISSIONING: {DeploymentStatus.DECOMMISSIONED, DeploymentStatus.FAILED},
    DeploymentStatus.DECOMMISSIONED: set(),
    DeploymentStatus.FAILED: {DeploymentStatus.PROVISIONING, DeploymentStatus.ACTIVE, DeploymentStatus.DECOMMISSIONING},
}


class InvalidTransition(Exception):
    pass


def validate_transition(current: DeploymentStatus, target: DeploymentStatus) -> None:
    if current == target:
        return  # idempotent no-op -- re-asserting the current status is always fine
    if target not in _VALID_TRANSITIONS.get(current, set()):
        raise InvalidTransition(f"cannot transition from '{current.value}' to '{target.value}'")


def stamp_schema(manifest: dict) -> dict:
    """Fills in schema_version/status on a manifest that predates this
    module (every manifest written by NOC-025/NOC-029 before this
    Issue) without disturbing anything already present. A pre-existing
    manifest represents an instance that was already deployed and
    running, so ACTIVE is the correct default status, not a guess."""
    manifest.setdefault("schema_version", SCHEMA_VERSION)
    manifest.setdefault("status", DeploymentStatus.ACTIVE.value)
    return manifest


def set_status(manifest: dict, new_status: DeploymentStatus, *, reason: str = "", now: Optional[str] = None) -> dict:
    """Mutates and returns `manifest` with a validated status
    transition, appending to status_history (same shape convention as
    scripts/upgrade.py's upgrade_history: timestamped, capped list)."""
    current_raw = manifest.get("status")
    current = DeploymentStatus(current_raw) if current_raw else None
    if current is not None:
        validate_transition(current, new_status)

    if now is None:
        from scripts import init_deployment
        now = init_deployment._utc_now()

    manifest["status"] = new_status.value
    manifest["updated_at"] = now
    history = manifest.setdefault("status_history", [])
    entry = {"timestamp": now, "from": current.value if current else None, "to": new_status.value}
    if reason:
        entry["reason"] = reason
    history.append(entry)
    del history[:-20]
    return manifest


def _find_sensitive_keys(obj, path: str = "") -> List[str]:
    """Recursively reports any key whose name looks like a secret,
    reusing app/structured_logging.py's own substring list rather than
    a second, divergent definition of "looks sensitive"."""
    offenders: List[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_path = f"{path}.{key}" if path else key
            lowered = key.lower()
            if any(s in lowered for s in _SENSITIVE_KEY_SUBSTRINGS):
                offenders.append(full_path)
            offenders.extend(_find_sensitive_keys(value, full_path))
    elif isinstance(obj, list):
        for item in obj:
            offenders.extend(_find_sensitive_keys(item, path))
    return offenders


def validate_manifest(manifest: dict) -> List[str]:
    """Returns a list of human-readable validation errors; empty means
    valid. Never raises on a malformed manifest -- that's the caller's
    call, same posture as every other operator script's Check-based
    reporting in this repo."""
    errors: List[str] = []

    deployment_id = manifest.get("deployment_id")
    if not deployment_id or not isinstance(deployment_id, str):
        errors.append("deployment_id is missing or not a string -- every other system reconciles against this id")

    if not manifest.get("created_at"):
        errors.append("created_at is missing")

    schema_version = manifest.get("schema_version")
    if schema_version is None:
        errors.append("schema_version is missing -- run stamp_schema() before validating a legacy manifest")
    elif not isinstance(schema_version, int) or schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
        errors.append(f"schema_version {schema_version!r} is not a supported version ({_SUPPORTED_SCHEMA_VERSIONS})")

    status = manifest.get("status")
    if status is not None:
        try:
            DeploymentStatus(status)
        except ValueError:
            errors.append(f"status {status!r} is not a valid DeploymentStatus")

    for field in _STRING_FIELDS:
        value = manifest.get(field)
        if value is not None and not isinstance(value, str):
            errors.append(f"{field} must be a string, got {type(value).__name__}")

    for field in _LIST_FIELDS:
        value = manifest.get(field)
        if value is not None and not isinstance(value, list):
            errors.append(f"{field} must be a list, got {type(value).__name__}")

    sensitive = _find_sensitive_keys(manifest)
    if sensitive:
        errors.append(f"manifest contains secret-looking key(s), which must never be stored here: {sensitive}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST_PATH)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="Validate the manifest and print any errors")

    set_status_parser = sub.add_parser("set-status", help="Validate and record a status transition")
    set_status_parser.add_argument("status", choices=[s.value for s in DeploymentStatus])
    set_status_parser.add_argument("--reason", default="")

    args = parser.parse_args()

    from scripts import init_deployment

    if args.command == "validate":
        manifest = init_deployment.load_manifest(args.manifest)
        errors = validate_manifest(manifest)
        if errors:
            for err in errors:
                print(f"FAIL {err}", file=sys.stderr)
            print(f"\n{len(errors)} error(s) in {args.manifest}.", file=sys.stderr)
            return 1
        print(f"OK manifest at {args.manifest} is valid (schema_version={manifest.get('schema_version')}).")
        return 0

    if args.command == "set-status":
        manifest = init_deployment.load_manifest(args.manifest)
        stamp_schema(manifest)
        try:
            set_status(manifest, DeploymentStatus(args.status), reason=args.reason)
        except InvalidTransition as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            return 1
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"OK status -> {args.status} ({args.manifest})")
        return 0

    return 2  # pragma: no cover - argparse's `required=True` makes this unreachable


if __name__ == "__main__":
    sys.exit(main())
