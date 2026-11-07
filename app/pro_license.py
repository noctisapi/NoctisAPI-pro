from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Optional

from app import license_runtime
from honey_licensing.client import compute_client_identity
from honey_licensing.managed_mode import resolve_managed_entitlements
from honey_licensing.offline_license import load_public_key_pem, resolve_local_license_state

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Online gate
# ---------------------------------------------------------------------------
# Set by app/license_online.py at startup via set_online_gate().
# When set, is_pro_enabled() requires BOTH offline valid AND online allowed.
# When None, online checks are not configured and offline validation is sufficient.
_ONLINE_GATE_LOCK = threading.Lock()
_ONLINE_GATE: Optional[Any] = None  # Callable[[], bool] | None


def set_online_gate(fn: Optional[Any]) -> None:
    """Register the online gate callback. Called once at app startup."""
    global _ONLINE_GATE
    with _ONLINE_GATE_LOCK:
        _ONLINE_GATE = fn


def _check_online_gate() -> bool:
    """Return True if online gate is not configured or allows PRO."""
    with _ONLINE_GATE_LOCK:
        gate = _ONLINE_GATE
    if gate is None:
        return True
    try:
        return bool(gate())
    except Exception:
        logger.warning("pro_license: online gate raised an exception; denying PRO as failsafe")
        return False


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
        "online_check_required": True,
    },
}

# Canonical product identifier — imported from honey_licensing.product (single source of truth).
from honey_licensing.product import PRODUCT_ID as _PRODUCT


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


def _instance_fingerprint() -> Optional[str]:
    fp = (os.getenv("INSTANCE_FINGERPRINT_SHA256") or "").strip()
    if fp:
        return fp
    try:
        identity = compute_client_identity()
        return str(identity.get("instance_fingerprint_sha256") or "").strip() or None
    except Exception:
        return None


def _fetch_managed_entitlements() -> tuple[bool, Optional[int], Optional[str], dict[str, Any]]:
    document_path = (
        license_runtime.get_effective("HP_MANAGED_ENTITLEMENTS_PATH")
        or os.getenv("HP_MANAGED_ENTITLEMENTS_PATH")
        or "/var/lib/myapp/managed_entitlements.json"
    ).strip()
    state_path = (
        license_runtime.get_effective("HP_MANAGED_ENTITLEMENTS_STATE_PATH")
        or os.getenv("HP_MANAGED_ENTITLEMENTS_STATE_PATH")
        or "/var/lib/myapp/managed_entitlements_state.json"
    ).strip()
    try:
        public_key = load_public_key_pem()
    except RuntimeError:
        return False, None, "MANAGED_PUBLIC_KEY_MISSING", {
            "tier": "core", "features": [], "mode": "managed",
            "source": "managed_entitlements", "license_generation": 0,
            "deployment_id": _runtime_deployment_id(), "online_check_required": False,
        }
    result = resolve_managed_entitlements(
        document_path=document_path,
        state_path=state_path,
        public_key_pem=public_key,
        deployment_id=_runtime_deployment_id(),
    )
    document = result.document
    features = sorted(document.features) if document else []
    expires_at = int(document.expires_at.timestamp()) if document and document.expires_at else None
    return result.valid, expires_at, (None if result.valid else result.reason_code), {
        "tier": "pro" if result.valid else "core",
        "features": features if result.valid else [],
        "mode": "managed",
        "source": "managed_entitlements",
        "license_generation": result.generation,
        "deployment_id": _runtime_deployment_id(),
        "plan_id": document.plan_id if document else None,
        "online_check_required": False,
    }


def _fetch_local_license() -> tuple[bool, Optional[int], Optional[str], dict[str, Any]]:
    mode = (
        license_runtime.get_effective("HP_LICENSE_MODE")
        or os.getenv("HP_LICENSE_MODE")
        or "offline"
    ).strip().lower()
    if mode == "managed":
        return _fetch_managed_entitlements()
    license_path, state_path = _license_paths()

    try:
        pub_pem = load_public_key_pem()
    except RuntimeError as exc:
        logger.error("license public key unavailable: %s", exc)
        meta: dict[str, Any] = {
            "tier": "core",
            "features": [],
            "source": "offline_license",
            "license_id": None,
            "license_generation": 0,
            "deployment_id": None,
            "reason_code": "LICENSE_PUBLIC_KEY_MISSING",
        }
        return False, None, "LICENSE_PUBLIC_KEY_MISSING", meta

    decision = resolve_local_license_state(
        license_path=license_path,
        state_path=state_path,
        runtime_deployment_id=_runtime_deployment_id(),
        public_key_pem=pub_pem,
        expected_product=_PRODUCT,
        instance_fingerprint=_instance_fingerprint(),
    )
    meta = {
        "tier": decision.tier,
        "features": list(decision.features),
        "source": decision.source,
        "license_id": decision.license_id,
        "license_generation": int(decision.license_generation or 0),
        "deployment_id": decision.deployment_id,
        "reason_code": decision.reason_code,
        "online_check_required": bool(decision.online_check_required),
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
    mode = str(meta.get("mode") or "self_hosted").strip().lower() or "self_hosted"
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
            "mode": mode,
        },
        "source": str(meta.get("source") or "offline_license"),
        "license_generation": int(meta.get("license_generation") or 0),
        "deployment_id": meta.get("deployment_id"),
        "license_id": meta.get("license_id"),
        "online_check_required": bool(meta.get("online_check_required", True)),
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
        str(ent.get("mode") or "").strip().lower() if isinstance(ent, dict) else "",
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
    """Return True only when BOTH offline validation passes AND the online gate allows.

    State machine:
      offline invalid                                                        => False
      offline valid + online_check_required=False                            => True  (offline-only license)
      offline valid + online_check_required=True + manager not configured    => False (fail-closed; HP_LICENSING_SERVER_URL not set)
      offline valid + online_check_required=True + no gate callback          => False (fail-closed; wiring missing)
      offline valid + online_check_required=True + online active             => True
      offline valid + online_check_required=True + online error (in grace)   => True
      offline valid + online_check_required=True + revoked/expired/no grace  => False
    """
    snapshot = get_backend_license_snapshot(force_refresh=False)
    if not snapshot.get("pro_enabled"):
        return False
    online_required = bool(snapshot.get("online_check_required", True))
    if not online_required:
        return True  # offline-only license; skip online gate entirely

    # online_check_required=True: the online manager MUST be configured.
    # Removing HP_LICENSING_SERVER_URL must not silently bypass this requirement —
    # is_online_allowed() returns True when no manager exists (offline-only mode),
    # but that must not satisfy a license that explicitly requires online validation.
    try:
        from app import license_online as _lo  # local import avoids circular dependency
        if _lo.get_manager() is None:
            logger.warning(
                "pro_license: online_check_required=True but online manager not configured "
                "(HP_LICENSING_SERVER_URL not set); denying PRO"
            )
            return False
    except Exception as exc:
        logger.warning("pro_license: could not check online manager status: %s; denying PRO", exc)
        return False

    with _ONLINE_GATE_LOCK:
        gate = _ONLINE_GATE
    if gate is None:
        logger.info("pro_license: online_check_required=True but no gate configured; denying PRO")
        return False
    return _check_online_gate()


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
            "online_check_required": True,
        }


def get_online_state_snapshot() -> Optional[dict[str, Any]]:
    """Return the current online license state dict, or None if not configured.

    Reads from the license_online manager without importing it at module level
    (avoids circular imports — license_online imports from pro_license).
    """
    try:
        from app import license_online  # local import to avoid circular dependency
        mgr = license_online.get_manager()
        if mgr is None:
            return None
        return mgr.get_online_state()
    except Exception:
        return None
