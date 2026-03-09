from __future__ import annotations

import hashlib
import os
import platform
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from honey_licensing.offline_license import load_trusted_public_keys_from_env, resolve_local_license_state


_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return bool(default)
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return int(default)
    try:
        return int(raw.strip())
    except Exception:
        return int(default)


def _read_text_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            val = (f.read() or "").strip()
            return val or None
    except Exception:
        return None


def get_or_create_uuid_file(path: str) -> str:
    path = (path or "").strip()
    if not path:
        raise ValueError("uuid path is empty")

    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

    try:
        with open(path, "r", encoding="utf-8") as f:
            val = (f.read() or "").strip()
            if val:
                uuid.UUID(val)
                return val
    except FileNotFoundError:
        pass
    except Exception:
        pass

    new_id = str(uuid.uuid4())
    tmp = f"{path}.tmp.{uuid.uuid4()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new_id + "\n")
    os.replace(tmp, path)
    return new_id


def compute_instance_fingerprint_sha256_hex() -> str:
    forced = (os.getenv("INSTANCE_FINGERPRINT_SHA256") or "").strip()
    if forced and _HEX64_RE.match(forced):
        return forced.lower()

    raw_override = (os.getenv("INSTANCE_FINGERPRINT_RAW") or "").strip()
    if raw_override:
        return hashlib.sha256(raw_override.encode("utf-8", errors="ignore")).hexdigest()

    host_mid_path = (os.getenv("HP_HOST_MACHINE_ID_PATH") or "/etc/host-machine-id").strip()
    parts: Dict[str, str] = {}
    parts["hostname"] = socket.gethostname()
    parts["platform"] = f"{platform.system()}|{platform.release()}|{platform.machine()}"
    parts["host_machine_id"] = _read_text_file(host_mid_path) or ""
    parts["machine_id"] = _read_text_file("/etc/machine-id") or _read_text_file("/var/lib/dbus/machine-id") or ""
    parts["product_uuid"] = _read_text_file("/sys/class/dmi/id/product_uuid") or ""
    parts["mac"] = f"{uuid.getnode():012x}"

    material = "\n".join(f"{k}={v}" for k, v in sorted(parts.items()) if v)
    if not material:
        material = f"hostname={socket.gethostname()}"

    return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()


def compute_client_identity() -> Dict[str, str]:
    instance_id_path = (os.getenv("INSTANCE_ID_PATH") or "/var/lib/myapp/instance_id").strip()
    instance_id = get_or_create_uuid_file(instance_id_path)
    fingerprint = compute_instance_fingerprint_sha256_hex()
    return {
        "instance_id": instance_id,
        "instance_id_path": instance_id_path,
        "instance_fingerprint_sha256": fingerprint,
    }


class LicensingClientError(RuntimeError):
    pass


class LicenseDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LIMITED = "LIMITED"


@dataclass(frozen=True)
class LicensingState:
    decision: Optional[str]
    valid: bool
    last_ok_at: Optional[datetime]
    last_error: Optional[str]
    reason_code: Optional[str]
    expires_at: Optional[int]
    entitlements: Dict[str, Any]
    recheck_after_seconds: Optional[int]


class LicensingStartupDenied(RuntimeError):
    pass


class LicensingManager:
    """
    Offline-only licensing manager.

    Single flow:
      license.json -> signature verify -> claims validate -> resolve PRO/CORE
    """

    def __init__(
        self,
        *,
        licensing_url: str,
        license_key: str,
        app_id: str,
        app_version: str,
        instance_id_path: str = "/var/lib/myapp/instance_id",
        http_timeout_seconds: float = 10.0,
        min_recheck_seconds: int = 30,
        max_recheck_seconds: Optional[int] = 300,
        enforce_on_startup: bool = False,
        limited_behavior: str = "core",
        deny_behavior: str = "disable",
    ) -> None:
        _ = (licensing_url, license_key, app_id, app_version, http_timeout_seconds, limited_behavior, deny_behavior)
        self._instance_id_path = (instance_id_path or "/var/lib/myapp/instance_id").strip()
        self._enforce_on_startup = bool(enforce_on_startup)
        self._min_recheck_seconds = max(5, int(min_recheck_seconds or 30))
        self._max_recheck_seconds = max_recheck_seconds if (max_recheck_seconds is not None and int(max_recheck_seconds) >= 5) else None

        self._lock = threading.Lock()
        self._state = LicensingState(
            decision=None,
            valid=False,
            last_ok_at=None,
            last_error="not_checked",
            reason_code="not_checked",
            expires_at=None,
            entitlements={},
            recheck_after_seconds=self._min_recheck_seconds,
        )
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def from_env() -> "LicensingManager":
        enforce = _env_bool("HP_ENFORCE_LICENSE", False)
        min_recheck = _env_int("HP_LICENSE_STATUS_REFRESH_SECONDS", 30)
        max_recheck = _env_int("HP_LICENSE_STATUS_MAX_REFRESH_SECONDS", 300)
        return LicensingManager(
            licensing_url="",
            license_key="",
            app_id="",
            app_version="",
            instance_id_path=(os.getenv("INSTANCE_ID_PATH") or "/var/lib/myapp/instance_id").strip(),
            min_recheck_seconds=min_recheck,
            max_recheck_seconds=max_recheck,
            enforce_on_startup=enforce,
        )

    def _offline_paths(self) -> tuple[str, str]:
        license_path = (
            os.getenv("HP_OFFLINE_LICENSE_PATH")
            or os.getenv("LICENSING_OFFLINE_LICENSE_PATH")
            or "/var/lib/myapp/license.json"
        ).strip()
        state_path = (
            os.getenv("HP_OFFLINE_LICENSE_STATE_PATH")
            or os.getenv("LICENSING_OFFLINE_LICENSE_STATE_PATH")
            or "/var/lib/myapp/license_state.json"
        ).strip()
        return license_path, state_path

    def _runtime_deployment_id(self) -> Optional[str]:
        configured = (os.getenv("HP_DEPLOYMENT_ID") or "").strip()
        if configured:
            return configured
        try:
            ident = compute_client_identity()
            return (str(ident.get("instance_id") or "").strip() or None)
        except Exception:
            return None

    def _validate_once(self) -> LicensingState:
        license_path, state_path = self._offline_paths()
        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=self._runtime_deployment_id(),
            trusted_public_keys=load_trusted_public_keys_from_env(),
        )

        now = datetime.now(timezone.utc)
        return LicensingState(
            decision=decision.decision,
            valid=bool(decision.valid and decision.tier == "pro"),
            last_ok_at=now if (decision.valid and decision.tier == "pro") else self.get_state().last_ok_at,
            last_error=None if (decision.valid and decision.tier == "pro") else decision.reason_code,
            reason_code=decision.reason_code,
            expires_at=decision.expires_at,
            entitlements=decision.entitlements,
            recheck_after_seconds=self._min_recheck_seconds,
        )

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()

        st = self.refresh_now()
        if self._enforce_on_startup and not st.valid:
            raise LicensingStartupDenied(f"Licensing invalid: {st.reason_code or st.last_error or 'unknown'}")

        t = threading.Thread(target=self._run, name="licensing-offline-recheck", daemon=True)
        with self._lock:
            self._thread = t
        t.start()

    def stop(self) -> None:
        self._stop.set()
        t = None
        with self._lock:
            t = self._thread
        if t and t.is_alive():
            t.join(timeout=3.0)

    def is_pro_enabled(self) -> bool:
        st = self.get_state()
        return bool(st.valid) and (st.decision == LicenseDecision.ALLOW.value)

    def get_state(self) -> LicensingState:
        with self._lock:
            return replace(self._state)

    def refresh_now(self) -> LicensingState:
        st = self._validate_once()
        with self._lock:
            self._state = st
        return st

    def _sleep_seconds(self) -> int:
        st = self.get_state()
        base = int(st.recheck_after_seconds or self._min_recheck_seconds)
        base = max(self._min_recheck_seconds, base)
        if self._max_recheck_seconds is not None:
            base = min(base, int(self._max_recheck_seconds))
        return max(5, int(base))

    def _run(self) -> None:
        while not self._stop.is_set():
            sleep_s = self._sleep_seconds()
            if self._stop.wait(timeout=float(sleep_s)):
                return
            self.refresh_now()


_DEFAULT_MANAGER_LOCK = threading.Lock()
_DEFAULT_MANAGER: Optional[LicensingManager] = None


def get_default_manager() -> LicensingManager:
    global _DEFAULT_MANAGER
    with _DEFAULT_MANAGER_LOCK:
        if _DEFAULT_MANAGER is None:
            _DEFAULT_MANAGER = LicensingManager.from_env()
        return _DEFAULT_MANAGER
