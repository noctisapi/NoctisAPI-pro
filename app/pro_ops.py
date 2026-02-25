from __future__ import annotations

import os
import threading
import time

from app import pro_license


_ALLOWLIST = {"cases", "campaigns", "replay", "advanced_scoring", "file_pipeline", "api_mutation", "analytics"}
_LEASE_FEATURE_ALIASES = {
    "api_mutation": {"api_mutation", "advanced_scoring", "campaigns"},
    "analytics": {"analytics", "advanced_scoring", "campaigns"},
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


def _canonical_action(action: str) -> str:
    return str(action or "access").strip().lower()


def _lease_allows_feature(feature_name: str, lease_features: set[str]) -> bool:
    aliases = _LEASE_FEATURE_ALIASES.get(feature_name, {feature_name})
    return any(name in lease_features for name in aliases)


def authorize_pro_feature(*, feature: str, action: str = "access", force_refresh: bool = False) -> tuple[bool, str]:
    feature_name = _canonical_feature(feature)
    action_name = _canonical_action(action)
    if feature_name not in _ALLOWLIST:
        return False, "unknown_feature"

    now = int(time.time())
    cache_ttl = _env_int("HP_PRO_OPS_AUTHZ_CACHE_SECONDS", 0, 0, 120)
    cache_key = f"{feature_name}|{action_name}"
    with _CACHE_LOCK:
        exp_cached = int(_CACHE.get(cache_key) or 0)
        if (not force_refresh) and cache_ttl > 0 and exp_cached > now + 2:
            return True, "ok_cached"

    lease_jws, lease_error, meta = pro_license.get_backend_lease(force_refresh=force_refresh)
    if not lease_jws:
        return False, lease_error or "missing_valid_lease"

    tier = str(meta.get("lease_tier") or "").strip().lower()
    if tier and tier != "pro":
        return False, "license_tier_not_pro"

    features_raw = meta.get("lease_features")
    features = set()
    if isinstance(features_raw, list):
        for item in features_raw:
            name = str(item or "").strip().lower()
            if name:
                features.add(name)
    if features and not _lease_allows_feature(feature_name, features):
        return False, "feature_not_in_lease"

    exp_raw = meta.get("lease_exp")
    try:
        exp = int(exp_raw) if exp_raw is not None else 0
    except Exception:
        exp = 0

    with _CACHE_LOCK:
        if cache_ttl > 0:
            ttl_exp = now + cache_ttl
            _CACHE[cache_key] = min(ttl_exp, exp) if exp > 0 else ttl_exp
        else:
            _CACHE[cache_key] = 0
    return True, "ok"


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
