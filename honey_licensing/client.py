from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import random
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key


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


def _safe_json_loads(raw: bytes) -> Dict[str, Any]:
    try:
        obj = json.loads((raw or b"").decode("utf-8", errors="replace") or "{}")
        return obj if isinstance(obj, dict) else {"_json": obj}
    except Exception as exc:
        preview = (raw or b"")[:500].decode("utf-8", errors="replace").strip()
        out: Dict[str, Any] = {"_error": f"invalid_json: {exc.__class__.__name__}"}
        if preview:
            out["_raw_preview"] = preview
        return out


def post_json(url: str, payload: Dict[str, Any], timeout: float) -> Tuple[int, Dict[str, Any]]:
    body = json.dumps(payload or {}).encode("utf-8")
    ua = (os.getenv("HP_HTTP_USER_AGENT") or "").strip()
    if not ua:
        app_id = (os.getenv("HP_APP_ID") or os.getenv("APP_ID") or "app").strip()
        app_ver = (os.getenv("HP_APP_VERSION") or os.getenv("APP_VERSION") or "").strip()
        ua = f"{app_id}/{app_ver}".rstrip("/") if app_ver else app_id
    req = Request(
        url=url,
        method="POST",
        data=body,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": ua,
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return int(getattr(resp, "status", 0) or 0), _safe_json_loads(raw)
    except HTTPError as exc:
        raw = b""
        try:
            raw = exc.read()  # type: ignore[attr-defined]
        except Exception:
            raw = b""
        return int(getattr(exc, "code", 0) or 0), _safe_json_loads(raw)
    except URLError as exc:
        return 0, {"_error": f"network_error: {exc.__class__.__name__}"}
    except (socket.timeout, TimeoutError) as exc:
        return 0, {"_error": f"timeout: {exc.__class__.__name__}"}
    except Exception as exc:
        return 0, {"_error": f"unexpected_error: {exc.__class__.__name__}"}


def _endpoint(licensing_url: str, path: str) -> str:
    base = (licensing_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("LICENSING_URL is empty")
    return f"{base}{path}"


class LicensingClientError(RuntimeError):
    def __init__(self, message: str, status_code: int = 0, data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = int(status_code or 0)
        self.data = data or {}


def _request_or_raise(
    *,
    url: str,
    payload: Dict[str, Any],
    timeout: float,
    post_json_func: Callable[[str, Dict[str, Any], float], Tuple[int, Dict[str, Any]]],
) -> Dict[str, Any]:
    status, data = post_json_func(url, payload, timeout)
    if status == 200:
        data = data or {}
        if isinstance(data, dict) and data.get("_error"):
            raise LicensingClientError(f"200: {data.get('_error')}", status_code=200, data=data)
        return data
    err = (data or {}).get("_error") or (data or {}).get("detail") or "http_error"
    raise LicensingClientError(f"{status or 0}: {err}", status_code=status, data=data or {})


def _b64url_decode(s: str) -> bytes:
    ss = (s or "").strip()
    if not ss:
        return b""
    pad = "=" * ((4 - (len(ss) % 4)) % 4)
    return base64.urlsafe_b64decode((ss + pad).encode("ascii"))


def verify_jws_rs256_compact(jws_compact: str, public_key_pem: bytes) -> Dict[str, Any]:
    """
    Verify JWS compact serialization "header.payload.signature" using RS256.
    Returns the decoded payload (dict).
    """
    parts = (jws_compact or "").strip().split(".")
    if len(parts) != 3:
        raise ValueError("invalid_jws_format")

    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    sig = _b64url_decode(parts[2])

    try:
        header = json.loads(header_raw.decode("utf-8", errors="strict"))
    except Exception:
        raise ValueError("invalid_jws_header_json")
    if not isinstance(header, dict):
        raise ValueError("invalid_jws_header_type")

    alg = str(header.get("alg") or "")
    if alg != "RS256":
        raise ValueError("unsupported_jws_alg")

    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    pub = load_pem_public_key(public_key_pem)
    pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())

    try:
        payload = json.loads(payload_raw.decode("utf-8", errors="strict"))
    except Exception:
        raise ValueError("invalid_jws_payload_json")
    if not isinstance(payload, dict):
        raise ValueError("invalid_jws_payload_type")
    return payload


_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _read_text_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            val = (f.read() or "").strip()
            return val or None
    except Exception:
        return None


def load_pinned_public_key_pem() -> bytes:
    path = (os.getenv("LICENSING_PINNED_PUBLIC_KEY_PATH") or "/app/app/licensing_server_public_key.pem").strip()
    with open(path, "rb") as f:
        return f.read()


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
                # Accept any valid UUID string.
                uuid.UUID(val)
                return val
    except FileNotFoundError:
        pass
    except Exception:
        # Invalid persisted value: overwrite with a fresh UUID.
        pass

    new_id = str(uuid.uuid4())
    tmp = f"{path}.tmp.{uuid.uuid4()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new_id + "\n")
    os.replace(tmp, path)
    return new_id


def compute_instance_fingerprint_sha256_hex() -> str:
    """
    Prefer an operator-provided hash (INSTANCE_FINGERPRINT_SHA256), otherwise compute
    a best-effort stable fingerprint material and return its SHA-256 hex (64 chars).
    """
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
        # Last-ditch: still return a stable hash for this container hostname.
        material = f"hostname={socket.gethostname()}"

    return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()


def compute_client_identity() -> Dict[str, str]:
    """
    Compute the identity tuple the licensing client presents to the licensing server.

    This is intentionally exposed for operator debugging (e.g. via /admin/license)
    so it's easy to resolve "FINGERPRINT_MISMATCH" issues by comparing what the app
    sends vs. what the licensing server has on record.
    """
    instance_id_path = (os.getenv("INSTANCE_ID_PATH") or "/var/lib/myapp/instance_id").strip()
    instance_id = get_or_create_uuid_file(instance_id_path)
    fingerprint = compute_instance_fingerprint_sha256_hex()
    return {
        "instance_id": instance_id,
        "instance_id_path": instance_id_path,
        "instance_fingerprint_sha256": fingerprint,
    }


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
    lease_jws: Optional[str] = None


class LicensingStartupDenied(RuntimeError):
    pass


class LicensingManager:
    """
    PRO policy (recommended):
    - Always call POST /v1/licenses/validate on startup, then periodically.
    - Always verify server_signature JWS RS256 using a pinned RSA public key (PEM).
    - Use the signed payload as the source of truth; reject if request_nonce/timestamp mismatch.
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
        min_recheck_seconds: int = 10,
        max_recheck_seconds: Optional[int] = 20,
        enforce_on_startup: bool = False,
        limited_behavior: str = "core",
        deny_behavior: str = "exit",
        post_json_func: Callable[[str, Dict[str, Any], float], Tuple[int, Dict[str, Any]]] = post_json,
    ) -> None:
        self._licensing_url = (licensing_url or "").strip()
        self._license_key = (license_key or "").strip()
        self._app_id = (app_id or "").strip()
        self._app_version = (app_version or "").strip()
        self._instance_id_path = (instance_id_path or "/var/lib/myapp/instance_id").strip()

        self._http_timeout_seconds = float(http_timeout_seconds or 10.0)
        self._min_recheck_seconds = max(1, int(min_recheck_seconds or 10))
        self._max_recheck_seconds: Optional[int] = None
        if max_recheck_seconds is not None:
            try:
                mr = int(max_recheck_seconds)
            except Exception:
                mr = 0
            if mr >= 1:
                self._max_recheck_seconds = mr
                # Avoid contradictory config (min > max) by shrinking min.
                if self._min_recheck_seconds > mr:
                    self._min_recheck_seconds = mr
        self._enforce_on_startup = bool(enforce_on_startup)
        self._limited_behavior = (limited_behavior or "core").strip().lower()
        self._deny_behavior = (deny_behavior or "exit").strip().lower()
        self._post_json = post_json_func

        self._lock = threading.Lock()
        self._validate_lock = threading.Lock()
        self._state = LicensingState(
            decision=None,
            valid=False,
            last_ok_at=None,
            last_error=None,
            reason_code=None,
            expires_at=None,
            entitlements={},
            recheck_after_seconds=None,
            lease_jws=None,
        )

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._instance_id: Optional[str] = None
        self._fingerprint_sha256: Optional[str] = None
        self._public_key_pem: Optional[bytes] = None

    @staticmethod
    def from_env() -> "LicensingManager":
        licensing_url = (os.getenv("LICENSING_URL") or "").strip()
        license_key = (os.getenv("LICENSE_KEY") or "").strip()
        app_id = (os.getenv("HP_APP_ID") or os.getenv("APP_ID") or "shadowapi-pro").strip()
        app_version = (os.getenv("HP_APP_VERSION") or os.getenv("APP_VERSION") or os.getenv("HP_API_VERSION") or "").strip()
        instance_id_path = (os.getenv("INSTANCE_ID_PATH") or "/var/lib/myapp/instance_id").strip()

        timeout = float(os.getenv("LICENSING_HTTP_TIMEOUT_SECONDS") or 10.0)
        # Intentionally NOT configurable by environment: the recheck interval is part of
        # the licensing enforcement and should not be user-tunable via `.env`.
        min_recheck = 60
        max_recheck_opt: Optional[int] = 600

        enforce = _env_bool("HP_ENFORCE_LICENSE", False)
        limited_behavior = (os.getenv("HP_LICENSE_LIMITED_BEHAVIOR") or "core").strip().lower()
        deny_behavior = (os.getenv("HP_LICENSE_DENY_BEHAVIOR") or "disable").strip().lower()

        return LicensingManager(
            licensing_url=licensing_url,
            license_key=license_key,
            app_id=app_id,
            app_version=app_version,
            instance_id_path=instance_id_path,
            http_timeout_seconds=timeout,
            min_recheck_seconds=min_recheck,
            max_recheck_seconds=max_recheck_opt,
            enforce_on_startup=enforce,
            limited_behavior=limited_behavior,
            deny_behavior=deny_behavior,
        )

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()

        # Always validate once on startup (fail-closed if enforcing).
        self._startup_validate()

        # No background loop without enough config.
        if not self._license_key or not self._licensing_url:
            return

        t = threading.Thread(target=self._run, name="licensing-recheck", daemon=True)
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

    def get_lease_jws(self) -> Optional[str]:
        st = self.get_state()
        if st.valid and st.decision == LicenseDecision.ALLOW.value and st.lease_jws:
            return st.lease_jws
        return None

    def refresh_now(self) -> LicensingState:
        with self._validate_lock:
            st = self._validate_once()
            self._set_state(st)
            return st

    def _set_state(self, st: LicensingState) -> None:
        with self._lock:
            self._state = st

    def _utc_now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _ensure_cached_identity(self) -> None:
        if self._instance_id is None:
            self._instance_id = get_or_create_uuid_file(self._instance_id_path)
        if self._fingerprint_sha256 is None:
            self._fingerprint_sha256 = compute_instance_fingerprint_sha256_hex()
        if self._public_key_pem is None:
            self._public_key_pem = load_pinned_public_key_pem()

    def _validate_once(self) -> LicensingState:
        if not self._license_key:
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=None,
                last_error="missing_LICENSE_KEY",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )
        if not self._licensing_url:
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=None,
                last_error="missing_LICENSING_URL",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )
        if not self._app_id:
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=None,
                last_error="missing_app_id",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )
        if not self._app_version:
            # Version is required by the API contract; treat missing as an error to avoid ambiguous telemetry.
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=None,
                last_error="missing_app_version",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )

        try:
            self._ensure_cached_identity()
        except Exception as exc:
            detail = (str(exc) or "").replace("\r", " ").replace("\n", " ").strip()
            detail = detail[:240] if detail else ""
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=self.get_state().last_ok_at,
                last_error=(
                    f"bad_client_identity:{exc.__class__.__name__}:{detail}"
                    if detail
                    else f"bad_client_identity:{exc.__class__.__name__}"
                ),
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )

        assert self._instance_id is not None
        assert self._fingerprint_sha256 is not None
        assert self._public_key_pem is not None

        nonce = uuid.uuid4().hex
        ts = int(time.time())
        req_payload = {
            "license_key": self._license_key,
            "app_id": self._app_id,
            "app_version": self._app_version,
            "instance_fingerprint": self._fingerprint_sha256,
            "instance_id": self._instance_id,
            "nonce": nonce,
            "timestamp": ts,
        }

        status, data = self._post_json(
            _endpoint(self._licensing_url, "/v1/licenses/validate"),
            req_payload,
            self._http_timeout_seconds,
        )
        data = data or {}
        if int(status or 0) == 0:
            # post_json encodes network/timeout failures as status=0 with an _error marker.
            err = str(data.get("_error") or "network_error")
            err = err.replace("\r", " ").replace("\n", " ").strip()
            if len(err) > 200:
                err = err[:200]
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=self.get_state().last_ok_at,
                last_error=err or "network_error",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )

        sig = str((data or {}).get("server_signature") or "").strip()
        if not sig:
            detail = str(data.get("_error") or data.get("detail") or "").strip()
            preview = str(data.get("_raw_preview") or "").strip()
            detail = detail.replace("\r", " ").replace("\n", " ").strip()
            if len(detail) > 180:
                detail = detail[:180]
            preview = preview.replace("\r", " ").replace("\n", " ").strip()
            if len(preview) > 220:
                preview = preview[:220]
            if preview and detail.startswith("invalid_json:"):
                detail = f"{detail} | {preview}"
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=self.get_state().last_ok_at,
                last_error=(
                    (f"http_{int(status or 0)}:{detail}" if detail else f"http_{int(status or 0)}")
                    if int(status or 0)
                    else "missing_server_signature"
                ),
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )

        try:
            payload = verify_jws_rs256_compact(sig, self._public_key_pem)
        except Exception as exc:
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=self.get_state().last_ok_at,
                last_error=f"bad_signature:{exc.__class__.__name__}",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )

        if str(payload.get("request_nonce") or "") != nonce:
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=self.get_state().last_ok_at,
                last_error="nonce_mismatch",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )
        try:
            rts = int(payload.get("request_timestamp") or 0)
        except Exception:
            rts = 0
        if rts != ts:
            return LicensingState(
                decision=None,
                valid=False,
                last_ok_at=self.get_state().last_ok_at,
                last_error="timestamp_mismatch",
                reason_code=None,
                expires_at=None,
                entitlements={},
                recheck_after_seconds=None,
                lease_jws=None,
            )

        decision = str(payload.get("decision") or "").strip().upper()
        decision_known = decision in (
            LicenseDecision.ALLOW.value,
            LicenseDecision.DENY.value,
            LicenseDecision.LIMITED.value,
        )
        # "valid" is a license validity flag coming from the server; denial can still be a
        # fully verified response (e.g. expired/revoked). We still require a known decision.
        valid = bool(payload.get("valid")) and decision_known
        reason_code = str(payload.get("reason_code") or "").strip() or None

        expires_at = payload.get("expires_at")
        try:
            expires_at_int = int(expires_at) if expires_at is not None else None
        except Exception:
            expires_at_int = None

        entitlements = payload.get("entitlements") if isinstance(payload.get("entitlements"), dict) else {}

        recheck = payload.get("recheck_after_seconds")
        try:
            recheck_int = int(recheck) if recheck is not None else None
        except Exception:
            recheck_int = None

        return LicensingState(
            decision=decision or None,
            valid=bool(valid),
            last_ok_at=self._utc_now() if valid else self.get_state().last_ok_at,
            # Signature + request binding verified: treat as a successful check even if
            # the license itself is not valid (DENY).
            last_error=None if decision_known else "invalid_payload",
            reason_code=reason_code,
            expires_at=expires_at_int,
            entitlements=entitlements,
            recheck_after_seconds=recheck_int,
            lease_jws=sig if decision_known else None,
        )

    def _startup_validate(self) -> None:
        st = self.refresh_now()

        if not self._enforce_on_startup:
            return

        if not st.valid:
            raise LicensingStartupDenied(f"Licensing invalid: {st.last_error or 'unknown'}")

        if st.decision == LicenseDecision.DENY.value:
            raise LicensingStartupDenied(f"License decision DENY (reason={st.reason_code or 'unknown'})")

        if st.decision == LicenseDecision.LIMITED.value and self._limited_behavior == "exit":
            raise LicensingStartupDenied(f"License decision LIMITED (reason={st.reason_code or 'unknown'})")

    def _sleep_seconds(self) -> int:
        st = self.get_state()
        now_ts = int(time.time())
        candidates = []
        raw = st.recheck_after_seconds
        if raw is not None:
            try:
                candidates.append(max(1, int(raw)))
            except Exception:
                pass
        if st.expires_at is not None:
            try:
                remain = int(st.expires_at) - now_ts
            except Exception:
                remain = 0
            if remain > 0:
                # Ensure at least one refresh shortly before lease expiration.
                candidates.append(max(10, remain - 30))
        if candidates:
            sleep_s = min(candidates)
        else:
            sleep_s = int(self._min_recheck_seconds)

        # Floor: do not check more frequently than min_recheck_seconds.
        sleep_s = max(int(self._min_recheck_seconds), int(sleep_s))
        # Ceiling: ensure changes in license state propagate promptly.
        if self._max_recheck_seconds is not None:
            sleep_s = min(int(sleep_s), int(self._max_recheck_seconds))
        # Add small jitter so many instances don't hit the server at the same second.
        jitter = max(1, int(sleep_s * 0.1))
        sleep_s += random.randint(-jitter, jitter)
        return max(1, int(sleep_s))

    def _run(self) -> None:
        while not self._stop.is_set():
            sleep_s = self._sleep_seconds()
            if self._stop.wait(timeout=float(sleep_s)):
                return

            st = self.refresh_now()

            if st.valid and st.decision == LicenseDecision.DENY.value and self._deny_behavior == "exit":
                # Best-effort immediate termination if the license is revoked while running.
                os._exit(3)


_DEFAULT_MANAGER_LOCK = threading.Lock()
_DEFAULT_MANAGER: Optional[LicensingManager] = None


def get_default_manager() -> LicensingManager:
    global _DEFAULT_MANAGER
    with _DEFAULT_MANAGER_LOCK:
        if _DEFAULT_MANAGER is None:
            _DEFAULT_MANAGER = LicensingManager.from_env()
        return _DEFAULT_MANAGER


def make_mock_post_json(responses: Dict[str, Tuple[int, Dict[str, Any]]]) -> Callable[[str, Dict[str, Any], float], Tuple[int, Dict[str, Any]]]:
    """
    Minimal mock: map absolute URL -> (status_code, json_dict).
    Useful for unit tests without hitting the network.
    """

    def _mock(url: str, payload: Dict[str, Any], timeout: float) -> Tuple[int, Dict[str, Any]]:
        _ = (payload, timeout)
        if url in responses:
            return responses[url]
        return 404, {"_error": "not_mocked"}

    return _mock
