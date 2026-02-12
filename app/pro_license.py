from __future__ import annotations

import base64
import json
import os
import threading
import time
from typing import Any, Optional

from app import campaigns_pro
from honey_licensing.client import compute_client_identity, load_pinned_public_key_pem, verify_jws_rs256_compact


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


def _b64url_decode_to_json(part: str) -> dict[str, Any]:
    raw = (part or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        obj = json.loads(decoded.decode("utf-8", errors="strict"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _best_effort_lease_exp(lease_jws: str) -> Optional[int]:
    parts = (lease_jws or "").split(".")
    if len(parts) != 3:
        return None
    payload = _b64url_decode_to_json(parts[1])
    raw_exp = payload.get("exp") if payload.get("exp") is not None else payload.get("expires_at")
    try:
        return int(raw_exp) if raw_exp is not None else None
    except Exception:
        return None


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
    }

    if not backend_url:
        return None, None, "missing_PRO_BACKEND_URL", meta
    if not license_key:
        return None, None, "missing_LICENSE_KEY", meta
    if not app_version:
        return None, None, "missing_app_version", meta
    if not instance_id or not instance_fingerprint:
        return None, None, "missing_instance_identity", meta

    try:
        lease_jws = campaigns_pro.get_backend_lease_cached(
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

    try:
        payload = _lease_payload(lease_jws)
    except Exception as exc:
        return None, None, f"lease_signature_invalid:{exc.__class__.__name__}", meta

    now = int(time.time())
    exp_raw = payload.get("exp") if payload.get("exp") is not None else payload.get("expires_at")
    try:
        exp = int(exp_raw) if exp_raw is not None else None
    except Exception:
        exp = None
    if exp is not None and exp <= now:
        return None, exp, "lease_expired", meta

    if str(payload.get("decision") or "").strip().upper() != "ALLOW":
        return None, exp, "license_decision_not_allow", meta
    if not bool(payload.get("valid")):
        return None, exp, "license_not_valid", meta

    exp_best_effort = _best_effort_lease_exp(lease_jws)
    return lease_jws, exp if exp is not None else exp_best_effort, None, meta


def get_backend_license_snapshot(*, force_refresh: bool = False) -> dict[str, Any]:
    now = int(time.time())
    min_refresh_seconds = _env_int("HP_BACKEND_LICENSE_STATUS_REFRESH_SECONDS", 15, 5, 300)

    with _STATUS_LOCK:
        checked_at = int(_STATUS_CACHE.get("checked_at") or 0)
        cached_snapshot = dict(_STATUS_CACHE.get("snapshot") or {})
        if not force_refresh and checked_at > 0 and (now - checked_at) < min_refresh_seconds:
            return cached_snapshot

    lease_jws, exp, error, _meta = _fetch_backend_lease(force_refresh=force_refresh)
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
        "entitlements": {},
        "source": "backend",
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
            "entitlements": {},
            "source": "backend",
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
