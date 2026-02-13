from __future__ import annotations

import os
import threading
import time
from typing import Any, Optional

from app import campaigns_pro
from honey_licensing.client import compute_client_identity, load_pinned_public_key_pem, verify_jws_rs256_compact


CLIENT_CAP_SECONDS = campaigns_pro.CLIENT_CAP_SECONDS
_STATUS_LOCK = threading.Lock()
_STATUS_CACHE: dict[str, Any] = {
    "checked_at": 0,
    "snapshot": {
        "pro_enabled": False,
        "valid": False,
        "decision": "DENY",
        "reason_code": "not_checked",
        "last_error": "not_checked",
        "last_ok_at": None,
        "expires_at": None,
        "expires_in_seconds": None,
        "recheck_after_seconds": None,
        "entitlements": {},
        "source": "backend",
    },
}


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


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _lease_payload(lease_jws: str) -> dict[str, Any]:
    public_key_pem = load_pinned_public_key_pem()
    return verify_jws_rs256_compact(lease_jws, public_key_pem)


def _normalize_features(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        name = str(item or "").strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _effective_grace_seconds(raw_offline_grace_seconds: Any) -> int:
    if raw_offline_grace_seconds is None:
        return int(CLIENT_CAP_SECONDS)
    try:
        val = int(raw_offline_grace_seconds)
    except Exception:
        raise ValueError("lease_offline_grace_invalid")
    return min(max(0, val), int(CLIENT_CAP_SECONDS))


def _fetch_backend_lease(*, force_refresh: bool) -> tuple[Optional[str], Optional[int], Optional[str], dict[str, Any]]:
    backend_url = campaigns_pro.pro_backend_url()
    app_id = (os.getenv("HP_APP_ID") or os.getenv("APP_ID") or "shadowapi-pro").strip()
    app_version = (os.getenv("HP_APP_VERSION") or os.getenv("APP_VERSION") or os.getenv("HP_API_VERSION") or "").strip()
    license_key = (os.getenv("LICENSE_KEY") or "").strip()
    identity = compute_client_identity()
    instance_id = str(identity.get("instance_id") or "").strip()
    instance_fingerprint = str(identity.get("instance_fingerprint_sha256") or "").strip()
    meta = {
        "backend_url": backend_url,
        "app_id": app_id,
        "app_version": app_version,
        "instance_id": instance_id,
        "instance_fingerprint": instance_fingerprint,
        "lease_tier": None,
        "lease_features": [],
        "lease_exp": None,
        "lease_issued_at": None,
        "lease_offline_grace_seconds": None,
        "lease_effective_grace_seconds": None,
        "lease_source": None,
    }

    if not license_key:
        return None, None, "missing_LICENSE_KEY", meta
    if not app_version:
        return None, None, "missing_app_version", meta
    if not instance_id or not instance_fingerprint:
        return None, None, "missing_instance_identity", meta

    try:
        lease_jws, lease_source = campaigns_pro.get_backend_lease_cached(
            backend_url=backend_url,
            license_key=license_key,
            app_id=app_id,
            app_version=app_version,
            instance_id=instance_id,
            instance_fingerprint=instance_fingerprint,
            force_refresh=force_refresh,
        )
    except campaigns_pro.CampaignProError as exc:
        return None, None, f"backend_lease_failed:{exc}", meta
    meta["lease_source"] = lease_source

    try:
        payload = _lease_payload(lease_jws)
    except Exception as exc:
        return None, None, f"lease_signature_invalid:{exc.__class__.__name__}", meta

    now = int(time.time())
    exp_raw = payload.get("exp")
    try:
        exp = int(exp_raw) if exp_raw is not None else None
    except Exception:
        exp = None
    if exp is None:
        return None, None, "lease_missing_exp", meta
    if exp <= now:
        return None, exp, "lease_expired", meta

    issued_at_raw = payload.get("issued_at")
    try:
        issued_at = int(issued_at_raw) if issued_at_raw is not None else None
    except Exception:
        issued_at = None
    if issued_at is None:
        return None, exp, "lease_missing_issued_at", meta
    if issued_at > now + 60:
        return None, exp, "lease_issued_at_in_future", meta

    claim_instance_id = str(payload.get("instance_id") or "").strip()
    if not claim_instance_id:
        return None, exp, "lease_missing_instance_id", meta
    if claim_instance_id != instance_id:
        return None, exp, "lease_instance_id_mismatch", meta

    claim_fp = str(payload.get("fingerprint_sha256") or "").strip()
    if not claim_fp:
        return None, exp, "lease_missing_fingerprint_sha256", meta
    if claim_fp != instance_fingerprint:
        return None, exp, "lease_fingerprint_mismatch", meta

    tier = str(payload.get("tier") or "").strip().lower()
    if not tier:
        return None, exp, "lease_missing_tier", meta
    if tier != "pro":
        return None, exp, f"license_tier_not_pro:{tier}", meta

    decision = str(payload.get("decision") or "").strip().upper()
    if decision and decision != "ALLOW":
        return None, exp, "license_decision_not_allow", meta

    valid_claim = payload.get("valid")
    if valid_claim is not None and not bool(valid_claim):
        return None, exp, "license_not_valid", meta

    if not isinstance(payload.get("features"), list):
        return None, exp, "lease_missing_features", meta
    features = _normalize_features(payload.get("features"))

    try:
        effective_grace = _effective_grace_seconds(payload.get("offline_grace_seconds"))
    except ValueError:
        return None, exp, "lease_offline_grace_invalid", meta
    if lease_source == "cache" and (now - issued_at) > effective_grace:
        return None, exp, "offline_grace_expired", meta

    meta["lease_tier"] = tier or "pro"
    meta["lease_features"] = features
    meta["lease_exp"] = int(exp)
    meta["lease_issued_at"] = int(issued_at)
    meta["lease_offline_grace_seconds"] = payload.get("offline_grace_seconds")
    meta["lease_effective_grace_seconds"] = int(effective_grace)

    return lease_jws, exp, None, meta


def get_backend_license_snapshot(*, force_refresh: bool = False) -> dict[str, Any]:
    now = int(time.time())
    min_refresh_seconds = _env_int("HP_BACKEND_LICENSE_STATUS_REFRESH_SECONDS", 15, 5, 300)

    with _STATUS_LOCK:
        checked_at = int(_STATUS_CACHE.get("checked_at") or 0)
        cached_snapshot = dict(_STATUS_CACHE.get("snapshot") or {})
        if not force_refresh and checked_at > 0 and (now - checked_at) < min_refresh_seconds:
            return cached_snapshot

    lease_jws, exp, error, meta = _fetch_backend_lease(force_refresh=force_refresh)
    expires_in = None
    if exp is not None:
        expires_in = int(exp) - now

    snapshot: dict[str, Any] = {
        "pro_enabled": bool(lease_jws),
        "valid": bool(lease_jws),
        "decision": "ALLOW" if lease_jws else "DENY",
        "reason_code": None if lease_jws else "backend_validation_failed",
        "last_error": error,
        "last_ok_at": _utc_now_iso() if lease_jws else None,
        "expires_at": exp,
        "expires_in_seconds": expires_in,
        "recheck_after_seconds": min_refresh_seconds,
        "entitlements": {
            "tier": meta.get("lease_tier"),
            "features": meta.get("lease_features") if isinstance(meta.get("lease_features"), list) else [],
        },
        "source": "backend_lease",
    }

    with _STATUS_LOCK:
        _STATUS_CACHE["checked_at"] = now
        _STATUS_CACHE["snapshot"] = snapshot
    return dict(snapshot)


def get_backend_lease(*, force_refresh: bool = False) -> tuple[Optional[str], Optional[str], dict[str, Any]]:
    lease_jws, exp, error, meta = _fetch_backend_lease(force_refresh=force_refresh)
    if not lease_jws:
        return None, error or "backend_lease_failed", meta
    now = int(time.time())
    expires_in = (int(exp) - now) if exp is not None else None
    with _STATUS_LOCK:
        _STATUS_CACHE["checked_at"] = now
        _STATUS_CACHE["snapshot"] = {
            "pro_enabled": True,
            "valid": True,
            "decision": "ALLOW",
            "reason_code": None,
            "last_error": None,
            "last_ok_at": _utc_now_iso(),
            "expires_at": int(exp) if exp is not None else None,
            "expires_in_seconds": expires_in,
            "recheck_after_seconds": _env_int("HP_BACKEND_LICENSE_STATUS_REFRESH_SECONDS", 15, 5, 300),
            "entitlements": {
                "tier": meta.get("lease_tier"),
                "features": meta.get("lease_features") if isinstance(meta.get("lease_features"), list) else [],
            },
            "source": "backend_lease",
        }
    return lease_jws, None, meta


def is_pro_enabled() -> bool:
    snapshot = get_backend_license_snapshot(force_refresh=False)
    return bool(snapshot.get("pro_enabled"))


def clear_cache() -> None:
    with _STATUS_LOCK:
        _STATUS_CACHE["checked_at"] = 0
        _STATUS_CACHE["snapshot"] = {
            "pro_enabled": False,
            "valid": False,
            "decision": "DENY",
            "reason_code": "not_checked",
            "last_error": "not_checked",
            "last_ok_at": None,
            "expires_at": None,
            "expires_in_seconds": None,
            "recheck_after_seconds": None,
            "entitlements": {},
            "source": "backend",
        }
