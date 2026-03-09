from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Optional

from app import license_runtime
from honey_licensing.client import compute_client_identity
from honey_licensing.offline_license import load_trusted_public_keys_from_env, resolve_local_license_state


_STATUS_LOCK = threading.Lock()
_STATUS_CACHE: dict[str, Any] = {
    "checked_at": 0,
    "snapshot": {
        "pro_enabled": False,
        "valid": False,
        "decision": "LIMITED",
        "reason_code": "not_checked",
        "last_error": "not_checked",
        "last_ok_at": None,
        "expires_at": None,
        "expires_in_seconds": None,
        "recheck_after_seconds": None,
        "entitlements": {},
        "source": "offline_license",
        "license_generation": 0,
        "deployment_id": None,
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


def _license_paths() -> tuple[str, str]:
    license_path = (
        license_runtime.get_effective("HP_OFFLINE_LICENSE_PATH")
        or os.getenv("LICENSING_OFFLINE_LICENSE_PATH")
        or "/var/lib/myapp/license.json"
    ).strip()
    state_path = (
        license_runtime.get_effective("HP_OFFLINE_LICENSE_STATE_PATH")
        or os.getenv("LICENSING_OFFLINE_LICENSE_STATE_PATH")
        or "/var/lib/myapp/license_state.json"
    ).strip()
    return license_path, state_path


def _runtime_deployment_id() -> Optional[str]:
    configured = (license_runtime.get_effective("HP_DEPLOYMENT_ID") or os.getenv("HP_DEPLOYMENT_ID") or "").strip()
    if configured:
        return configured
    try:
        identity = compute_client_identity()
        inst = str(identity.get("instance_id") or "").strip()
        return inst or None
    except Exception:
        return None


def _merge_keys_from_json_text(keys: dict[str, str], raw_json: str) -> None:
    raw = str(raw_json or "").strip()
    if not raw:
        return
    try:
        obj = json.loads(raw)
    except Exception:
        return
    if not isinstance(obj, dict):
        return
    for k, v in obj.items():
        kid = str(k or "").strip()
        raw_key = str(v or "").strip()
        if kid and raw_key:
            keys[kid] = raw_key


def _merge_keys_from_path(keys: dict[str, str], path: str) -> None:
    key_path = str(path or "").strip()
    if not key_path:
        return
    try:
        with open(key_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception:
        return
    if not isinstance(obj, dict):
        return
    for k, v in obj.items():
        kid = str(k or "").strip()
        raw_key = str(v or "").strip()
        if kid and raw_key:
            keys[kid] = raw_key


def _bundled_keys_path() -> str:
    return (os.getenv("HP_OFFLINE_PUBLIC_KEYS_BUNDLE_PATH") or "/app/app/offline_public_keys.json").strip()


def load_effective_trusted_public_keys() -> dict[str, str]:
    """
    Build trusted key map using bundled image keys + env + runtime overrides.
    Runtime overrides win over plain env values, and env wins over bundled defaults.
    """
    keys: dict[str, str] = {}
    _merge_keys_from_path(keys, _bundled_keys_path())
    env_keys = load_trusted_public_keys_from_env()
    for kid, raw_key in env_keys.items():
        keys[str(kid)] = str(raw_key)
    _merge_keys_from_json_text(keys, license_runtime.get_effective("HP_OFFLINE_PUBLIC_KEYS_JSON"))
    _merge_keys_from_json_text(keys, os.getenv("LICENSING_OFFLINE_PUBLIC_KEYS_JSON") or "")
    _merge_keys_from_path(
        keys,
        license_runtime.get_effective("HP_OFFLINE_PUBLIC_KEYS_PATH")
        or os.getenv("LICENSING_OFFLINE_PUBLIC_KEYS_PATH")
        or "",
    )
    return keys


def _fetch_local_license() -> tuple[bool, Optional[int], Optional[str], dict[str, Any]]:
    license_path, state_path = _license_paths()
    trusted_keys = load_effective_trusted_public_keys()
    decision = resolve_local_license_state(
        license_path=license_path,
        state_path=state_path,
        runtime_deployment_id=_runtime_deployment_id(),
        trusted_public_keys=trusted_keys,
    )
    meta = {
        "tier": decision.tier,
        "features": list(decision.features),
        "source": decision.source,
        "license_id": decision.license_id,
        "license_generation": int(decision.license_generation or 0),
        "deployment_id": decision.deployment_id,
        "reason_code": decision.reason_code,
    }
    return bool(decision.valid), decision.expires_at, (None if decision.valid else decision.reason_code), meta


def _snapshot_from_local_result(
    *,
    valid: bool,
    exp: Optional[int],
    error: Optional[str],
    meta: dict[str, Any],
    recheck_after_seconds: int,
) -> dict[str, Any]:
    now = int(time.time())
    expires_in = None
    if exp is not None:
        expires_in = int(exp) - now
    tier = str(meta.get("tier") or "core").strip().lower() or "core"
    features = list(meta.get("features") or []) if isinstance(meta.get("features"), list) else []
    return {
        "pro_enabled": bool(valid and tier == "pro"),
        "valid": bool(valid),
        "decision": "ALLOW" if valid and tier == "pro" else "LIMITED",
        "reason_code": "OK" if valid else (str(error or "OFFLINE_INVALID").strip().upper() or "OFFLINE_INVALID"),
        "last_error": None if valid else (str(error or "OFFLINE_INVALID").strip()),
        "last_ok_at": _utc_now_iso() if valid else None,
        "expires_at": exp,
        "expires_in_seconds": expires_in,
        "recheck_after_seconds": recheck_after_seconds,
        "entitlements": {
            "tier": tier,
            "features": features if tier == "pro" else [],
        },
        "source": "offline_license",
        "license_generation": int(meta.get("license_generation") or 0),
        "deployment_id": meta.get("deployment_id"),
        "license_id": meta.get("license_id"),
    }


def _snapshot_state_key(snapshot: dict[str, Any]) -> tuple[Any, ...]:
    ent = snapshot.get("entitlements") if isinstance(snapshot.get("entitlements"), dict) else {}
    raw_features = ent.get("features") if isinstance(ent, dict) else []
    features = sorted({str(x or "").strip().lower() for x in (raw_features or []) if str(x or "").strip()})
    return (
        bool(snapshot.get("valid")),
        str(snapshot.get("decision") or "").strip().upper(),
        str(snapshot.get("reason_code") or "").strip(),
        int(snapshot.get("expires_at") or 0),
        str(ent.get("tier") or "").strip().lower() if isinstance(ent, dict) else "",
        tuple(features),
        int(snapshot.get("license_generation") or 0),
        str(snapshot.get("deployment_id") or "").strip(),
    )


def get_backend_license_snapshot(*, force_refresh: bool = False) -> dict[str, Any]:
    now = int(time.time())
    min_refresh_seconds = _env_int("HP_LICENSE_STATUS_REFRESH_SECONDS", 15, 5, 300)

    with _STATUS_LOCK:
        checked_at = int(_STATUS_CACHE.get("checked_at") or 0)
        cached_snapshot = dict(_STATUS_CACHE.get("snapshot") or {})
        if not force_refresh and checked_at > 0 and (now - checked_at) < min_refresh_seconds:
            return cached_snapshot

    valid, exp, error, meta = _fetch_local_license()
    snapshot = _snapshot_from_local_result(
        valid=valid,
        exp=exp,
        error=error,
        meta=meta,
        recheck_after_seconds=min_refresh_seconds,
    )
    _ = _snapshot_state_key(snapshot) != _snapshot_state_key(cached_snapshot)

    with _STATUS_LOCK:
        _STATUS_CACHE["checked_at"] = int(time.time())
        _STATUS_CACHE["snapshot"] = snapshot
    return dict(snapshot)


def is_pro_enabled() -> bool:
    snapshot = get_backend_license_snapshot(force_refresh=False)
    return bool(snapshot.get("pro_enabled"))


def clear_cache() -> None:
    with _STATUS_LOCK:
        _STATUS_CACHE["checked_at"] = 0
        _STATUS_CACHE["snapshot"] = {
            "pro_enabled": False,
            "valid": False,
            "decision": "LIMITED",
            "reason_code": "not_checked",
            "last_error": "not_checked",
            "last_ok_at": None,
            "expires_at": None,
            "expires_in_seconds": None,
            "recheck_after_seconds": None,
            "entitlements": {},
            "source": "offline_license",
            "license_generation": 0,
            "deployment_id": None,
        }
