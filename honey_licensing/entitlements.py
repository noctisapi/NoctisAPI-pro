"""Versioned Managed/self-hosted entitlement contract (NOC-040).

Entitlements describe what the product may do.  They deliberately contain no
payment-provider, subscription, or user-role fields.  Authentication of the
document remains the responsibility of the signed-license/Managed config
layer; this module validates and evaluates an already-authenticated mapping.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Optional


ENTITLEMENTS_SCHEMA_VERSION = 1
ENTITLEMENT_MODES = frozenset({"managed", "self_hosted"})
KNOWN_FEATURES = frozenset({
    "cases",
    "campaigns",
    "replay",
    "advanced_scoring",
    "file_pipeline",
    "api_mutation",
    "analytics",
    "webhooks",
    "log_export",
})
_QUOTA_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FORBIDDEN_FIELDS = frozenset({
    "billing_provider",
    "payment_status",
    "price_id",
    "subscription_id",
    "user_roles",
    "permissions",
})


class EntitlementValidationError(ValueError):
    """The entitlement document is not a valid versioned contract."""


def _parse_time(value: Any, field: str, *, required: bool = False) -> Optional[datetime]:
    if value in (None, ""):
        if required:
            raise EntitlementValidationError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise EntitlementValidationError(f"{field} must be an ISO-8601 string")
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise EntitlementValidationError(f"{field} must be an ISO-8601 string") from exc
    if parsed.tzinfo is None:
        raise EntitlementValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class EntitlementDocument:
    schema_version: int
    plan_id: str
    mode: str
    features: frozenset[str]
    quotas: dict[str, int]
    starts_at: datetime
    expires_at: Optional[datetime] = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "EntitlementDocument":
        if not isinstance(raw, Mapping):
            raise EntitlementValidationError("entitlements must be an object")
        forbidden = sorted(_FORBIDDEN_FIELDS.intersection(raw.keys()))
        if forbidden:
            raise EntitlementValidationError(
                "entitlements must not contain billing or user-permission fields: "
                + ", ".join(forbidden)
            )
        try:
            version = int(raw.get("schema_version"))
        except (TypeError, ValueError) as exc:
            raise EntitlementValidationError("schema_version must be an integer") from exc
        if version != ENTITLEMENTS_SCHEMA_VERSION:
            raise EntitlementValidationError(f"unsupported entitlement schema_version: {version}")

        plan_id = str(raw.get("plan_id") or "").strip()
        if not plan_id or len(plan_id) > 100:
            raise EntitlementValidationError("plan_id must be a non-empty bounded string")
        mode = str(raw.get("mode") or "").strip().lower()
        if mode not in ENTITLEMENT_MODES:
            raise EntitlementValidationError("mode must be managed or self_hosted")

        features_raw = raw.get("features")
        if not isinstance(features_raw, (list, tuple, set, frozenset)):
            raise EntitlementValidationError("features must be a list")
        features = frozenset(str(item or "").strip().lower() for item in features_raw)
        features = frozenset(item for item in features if item)
        unknown = sorted(features - KNOWN_FEATURES)
        if unknown:
            raise EntitlementValidationError("unknown entitlement feature(s): " + ", ".join(unknown))

        quotas_raw = raw.get("quotas", {})
        if not isinstance(quotas_raw, Mapping):
            raise EntitlementValidationError("quotas must be an object")
        quotas: dict[str, int] = {}
        for name, value in quotas_raw.items():
            quota_name = str(name or "").strip().lower()
            if not _QUOTA_NAME.fullmatch(quota_name):
                raise EntitlementValidationError(f"invalid quota name: {name}")
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EntitlementValidationError(f"quota {quota_name} must be a non-negative integer")
            quotas[quota_name] = value

        starts_at = _parse_time(raw.get("starts_at"), "starts_at", required=True)
        expires_at = _parse_time(raw.get("expires_at"), "expires_at")
        if expires_at is not None and expires_at <= starts_at:
            raise EntitlementValidationError("expires_at must be later than starts_at")
        return cls(version, plan_id, mode, features, quotas, starts_at, expires_at)

    def to_mapping(self) -> dict[str, Any]:
        def iso(value: Optional[datetime]) -> Optional[str]:
            return value.isoformat().replace("+00:00", "Z") if value else None

        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "mode": self.mode,
            "features": sorted(self.features),
            "quotas": dict(sorted(self.quotas.items())),
            "starts_at": iso(self.starts_at),
        }
        if self.expires_at is not None:
            result["expires_at"] = iso(self.expires_at)
        return result


@dataclass(frozen=True)
class EntitlementDecision:
    allowed: bool
    reason: str
    quota: Optional[int] = None


def evaluate(
    document: EntitlementDocument,
    feature: str,
    *,
    now: Optional[datetime] = None,
    usage: Optional[int] = None,
    quota_name: Optional[str] = None,
) -> EntitlementDecision:
    """Evaluate capability and optional quota, independently of user roles."""
    feature_name = str(feature or "").strip().lower()
    if feature_name not in KNOWN_FEATURES:
        return EntitlementDecision(False, "unknown_feature")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < document.starts_at:
        return EntitlementDecision(False, "not_started")
    if document.expires_at is not None and current >= document.expires_at:
        return EntitlementDecision(False, "expired")
    if feature_name not in document.features:
        return EntitlementDecision(False, "feature_not_entitled")
    if usage is None or quota_name is None or quota_name not in document.quotas:
        return EntitlementDecision(True, "allowed")
    if usage < 0:
        return EntitlementDecision(False, "invalid_usage", document.quotas[quota_name])
    quota = document.quotas[quota_name]
    if usage >= quota:
        return EntitlementDecision(False, "quota_exceeded", quota)
    return EntitlementDecision(True, "allowed", quota)
