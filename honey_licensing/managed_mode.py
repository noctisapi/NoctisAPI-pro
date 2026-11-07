"""Authenticated Managed Mode entitlement loader (NOC-041).

The instance receives a signed entitlement envelope from the operator.  It
does not contain a private key and cannot turn Managed Mode on by setting a
boolean.  The envelope is bound to the deployment id and its monotonically
increasing generation is persisted to prevent rollback.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from honey_licensing.entitlements import EntitlementDocument, EntitlementValidationError
from honey_licensing.offline_license import LicenseVerifier


class ManagedEntitlementError(RuntimeError):
    """Managed entitlement authentication or validation failed."""


@dataclass(frozen=True)
class ManagedEntitlementResult:
    valid: bool
    reason_code: str
    generation: int
    document: Optional[EntitlementDocument]


def _load_json(path: Path) -> Optional[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix="managed-entitlements-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _runtime_deployment_id() -> str:
    return (os.getenv("HP_DEPLOYMENT_ID") or "").strip()


def resolve_managed_entitlements(
    *,
    document_path: str,
    state_path: str,
    public_key_pem: bytes,
    deployment_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> ManagedEntitlementResult:
    """Verify one signed Managed envelope and persist its highest generation."""
    raw = _load_json(Path(document_path))
    if not raw:
        return ManagedEntitlementResult(False, "MANAGED_ENTITLEMENTS_MISSING", 0, None)
    try:
        verifier = LicenseVerifier(public_key_pem=public_key_pem)
    except Exception:
        return ManagedEntitlementResult(False, "MANAGED_PUBLIC_KEY_INVALID", 0, None)
    ok, payload, reason = verifier.verify(raw)
    if not ok or payload is None:
        return ManagedEntitlementResult(False, "MANAGED_" + reason.upper(), 0, None)

    product = str(payload.get("product") or "").strip().lower()
    if product != "noctisapi":
        return ManagedEntitlementResult(False, "MANAGED_PRODUCT_MISMATCH", 0, None)
    expected_deployment = (deployment_id or _runtime_deployment_id()).strip()
    envelope_deployment = str(payload.get("deployment_id") or "").strip()
    if not expected_deployment or envelope_deployment != expected_deployment:
        return ManagedEntitlementResult(False, "MANAGED_DEPLOYMENT_MISMATCH", 0, None)
    try:
        generation = int(payload.get("generation"))
    except (TypeError, ValueError):
        return ManagedEntitlementResult(False, "MANAGED_GENERATION_INVALID", 0, None)
    if generation < 1:
        return ManagedEntitlementResult(False, "MANAGED_GENERATION_INVALID", generation, None)

    try:
        entitlements = EntitlementDocument.from_mapping(payload.get("entitlements") or {})
    except EntitlementValidationError as exc:
        return ManagedEntitlementResult(False, "MANAGED_ENTITLEMENTS_INVALID", generation, None)
    if entitlements.mode != "managed":
        return ManagedEntitlementResult(False, "MANAGED_MODE_REQUIRED", generation, None)

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if entitlements.expires_at is not None and current >= entitlements.expires_at:
        return ManagedEntitlementResult(False, "MANAGED_ENTITLEMENTS_EXPIRED", generation, None)
    if current < entitlements.starts_at:
        return ManagedEntitlementResult(False, "MANAGED_ENTITLEMENTS_NOT_STARTED", generation, None)

    state = _load_json(Path(state_path)) or {}
    maximum = int(state.get("max_generation") or 0)
    if generation < maximum:
        return ManagedEntitlementResult(False, "MANAGED_ROLLBACK_DETECTED", generation, None)
    if generation > maximum:
        _write_json(Path(state_path), {"max_generation": generation, "deployment_id": expected_deployment})
    return ManagedEntitlementResult(True, "OK", generation, entitlements)


def signed_envelope_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical bytes helper for the operator-side signing tool/tests."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
