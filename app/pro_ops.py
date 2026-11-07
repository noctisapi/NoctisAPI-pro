from __future__ import annotations

import os
import threading
import time

from app import pro_license


_ALLOWLIST = {"cases", "campaigns", "replay", "advanced_scoring", "file_pipeline", "api_mutation", "analytics", "webhooks", "log_export"}
_LEASE_FEATURE_ALIASES = {
    "api_mutation": {"api_mutation", "advanced_scoring", "campaigns"},
    "analytics": {"analytics", "advanced_scoring", "campaigns"},
    "log_export": {"log_export", "webhooks", "cases", "campaigns", "api_mutation", "analytics"},
}
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, int] = {}


def _env_int(name: str, default: int, min_value: int, max_value: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        val = int(default)
    else:
        try:
            val = int(raw.strip())
        except Exception:
            val = int(default)
    return max(min_value, min(max_value, val))


def _canonical_feature(feature: str) -> str:
    return str(feature or "").strip().lower()



def _lease_allows_feature(feature_name: str, lease_features: set[str]) -> bool:
    aliases = _LEASE_FEATURE_ALIASES.get(feature_name, {feature_name})
    return any(name in lease_features for name in aliases)


def authorize_pro_feature(*, feature: str, action: str = "access", force_refresh: bool = False) -> tuple[bool, str]:
    feature_name = _canonical_feature(feature)
    if feature_name not in _ALLOWLIST:
        return False, "unknown_feature"

    # Authoritative decision now comes from local signed license.json validation.
    # Snapshot cache only controls local re-check frequency.
    snapshot = pro_license.get_backend_license_snapshot(force_refresh=force_refresh)
    if not snapshot.get("pro_enabled") or not snapshot.get("valid"):
        reason = snapshot.get("reason_code") or snapshot.get("last_error") or "pro_not_enabled"
        return False, str(reason)

    ent = snapshot.get("entitlements") if isinstance(snapshot.get("entitlements"), dict) else {}
    mode = str(ent.get("mode") or "self_hosted").strip().lower() if isinstance(ent, dict) else "self_hosted"
    tier = str(ent.get("tier") or "").strip().lower() if isinstance(ent, dict) else ""
    if tier and tier != "pro":
        return False, "license_tier_not_pro"

    features_raw = ent.get("features") if isinstance(ent, dict) else []
    features: set[str] = set()
    if isinstance(features_raw, list):
        for item in features_raw:
            name = str(item or "").strip().lower()
            if name:
                features.add(name)
    if mode == "managed" and not features:
        return False, "feature_not_in_entitlement"
    if features and not _lease_allows_feature(feature_name, features):
        # Backward compatibility: Log Export was added after existing Pro
        # licenses were issued, so older leases may not list it explicitly.
        # A valid Pro lease is sufficient for this feature.
        if feature_name == "log_export":
            return True, "ok"
        return False, "feature_not_in_lease"

    return True, "ok"


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
