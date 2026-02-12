from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Any

import httpx

from app import campaigns_pro
from app import pro_license
from honey_licensing.client import verify_jws_rs256_compact


_ALLOWLIST = {"cases", "campaigns", "replay", "advanced_scoring", "file_pipeline"}
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


def _request_fingerprint(*, feature: str, action: str, app_id: str, instance_id: str) -> str:
    material = f"{feature}|{action}|{app_id}|{instance_id}"
    return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()


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

    backend_url = str(meta.get("backend_url") or "").strip().rstrip("/")
    app_id = str(meta.get("app_id") or "").strip()
    instance_id = str(meta.get("instance_id") or "").strip()
    if not backend_url or not app_id or not instance_id:
        return False, "missing_backend_identity"

    request_fp = _request_fingerprint(feature=feature_name, action=action_name, app_id=app_id, instance_id=instance_id)
    payload = {
        "feature": feature_name,
        "action": action_name,
        "app_id": app_id,
        "instance_id": instance_id,
        "request_fingerprint": request_fp,
    }
    headers = {"authorization": f"Bearer {lease_jws}"}

    timeout_s = float(_env_int("HP_PRO_OPS_HTTP_TIMEOUT_SECONDS", 8, 2, 30))
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.post(f"{backend_url}/v1/pro/features/authorize", json=payload, headers=headers)
    except Exception as exc:
        return False, f"backend_authorize_transport_error:{exc.__class__.__name__}"
    if resp.status_code != 200:
        return False, f"backend_authorize_failed:{resp.status_code}"

    try:
        data = resp.json() if resp.content else {}
    except Exception:
        return False, "backend_authorize_invalid_json"
    if not isinstance(data, dict):
        return False, "backend_authorize_invalid_response"
    if not bool(data.get("authorized")):
        return False, "backend_authorize_denied"

    auth_sig = str(data.get("auth_sig") or "").strip()
    if not auth_sig:
        return False, "backend_authorize_missing_signature"
    try:
        public_key_pem = campaigns_pro.load_results_public_key_pem()
        signed = verify_jws_rs256_compact(auth_sig, public_key_pem)
    except Exception as exc:
        return False, f"backend_authorize_signature_invalid:{exc.__class__.__name__}"

    now = int(time.time())
    exp_raw = signed.get("exp") if signed.get("exp") is not None else signed.get("expires_at")
    try:
        exp = int(exp_raw) if exp_raw is not None else 0
    except Exception:
        exp = 0
    if exp <= now:
        return False, "backend_authorize_expired"
    if str(signed.get("op") or "") != "pro_feature_authorize":
        return False, "backend_authorize_op_mismatch"
    if str(signed.get("feature") or "") != feature_name:
        return False, "backend_authorize_feature_mismatch"
    if str(signed.get("action") or "") != action_name:
        return False, "backend_authorize_action_mismatch"
    if not bool(signed.get("authorized")):
        return False, "backend_authorize_not_authorized"
    if str(signed.get("app_id") or "") != app_id:
        return False, "backend_authorize_app_id_mismatch"
    if str(signed.get("instance_id") or "") != instance_id:
        return False, "backend_authorize_instance_id_mismatch"
    if str(signed.get("request_fingerprint") or "") != request_fp:
        return False, "backend_authorize_request_mismatch"

    with _CACHE_LOCK:
        _CACHE[cache_key] = exp if cache_ttl > 0 else 0
    return True, "ok"


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
