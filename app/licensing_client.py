from __future__ import annotations

import json
import os
import socket
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def get_or_create_fingerprint(path: str) -> str:
    path = (path or "").strip()
    if not path:
        raise ValueError("fingerprint path is empty")

    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

    try:
        with open(path, "r", encoding="utf-8") as f:
            val = (f.read() or "").strip()
            if val:
                return val
    except FileNotFoundError:
        pass

    fp = str(uuid.uuid4())
    tmp = f"{path}.tmp.{uuid.uuid4()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(fp + "\n")
    os.replace(tmp, path)
    return fp


def _safe_json_loads(raw: bytes) -> Dict[str, Any]:
    try:
        obj = json.loads((raw or b"").decode("utf-8", errors="replace") or "{}")
        return obj if isinstance(obj, dict) else {"_json": obj}
    except Exception as exc:
        return {"_error": f"invalid_json: {exc.__class__.__name__}"}


def post_json(url: str, payload: Dict[str, Any], timeout: float) -> Tuple[int, Dict[str, Any]]:
    body = json.dumps(payload or {}).encode("utf-8")
    req = Request(
        url=url,
        method="POST",
        data=body,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return int(getattr(resp, "status", 0) or 0), _safe_json_loads(raw)
    except HTTPError as exc:
        # HTTPError is also a file-like object.
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
        # Treat "200 but invalid JSON" (or similar parse issues) as a failure.
        if isinstance(data, dict) and data.get("_error"):
            raise LicensingClientError(f"200: {data.get('_error')}", status_code=200, data=data)
        return data
    err = (data or {}).get("_error") or (data or {}).get("detail") or "http_error"
    raise LicensingClientError(f"{status or 0}: {err}", status_code=status, data=data or {})


def activate(licensing_url: str, license_key: str, fingerprint: str, *, timeout: float = 10.0) -> Dict[str, Any]:
    return _request_or_raise(
        url=_endpoint(licensing_url, "/v1/activate"),
        payload={"license_key": license_key, "fingerprint": fingerprint},
        timeout=timeout,
        post_json_func=post_json,
    )


def validate(licensing_url: str, license_key: str, fingerprint: str, *, timeout: float = 10.0) -> Dict[str, Any]:
    return _request_or_raise(
        url=_endpoint(licensing_url, "/v1/validate"),
        payload={"license_key": license_key, "fingerprint": fingerprint},
        timeout=timeout,
        post_json_func=post_json,
    )


def deactivate(licensing_url: str, license_key: str, fingerprint: str, *, timeout: float = 10.0) -> Dict[str, Any]:
    return _request_or_raise(
        url=_endpoint(licensing_url, "/v1/deactivate"),
        payload={"license_key": license_key, "fingerprint": fingerprint},
        timeout=timeout,
        post_json_func=post_json,
    )


@dataclass(frozen=True)
class LicensingState:
    pro_enabled: bool
    last_ok_at: Optional[datetime]
    last_error: Optional[str]
    session_token: Optional[str]


class LicensingManager:
    """
    Policy: if any activation/validation fails (HTTP != 200, 429, network, timeout, JSON errors),
    PRO is turned OFF immediately. Background loop keeps retrying (bounded by min renew seconds).
    """

    def __init__(
        self,
        *,
        licensing_url: str,
        license_key: str,
        fingerprint_path: str = "/var/lib/myapp/device_fingerprint",
        http_timeout_seconds: float = 10.0,
        min_renew_seconds: int = 30,
        post_json_func: Callable[[str, Dict[str, Any], float], Tuple[int, Dict[str, Any]]] = post_json,
    ) -> None:
        self._licensing_url = (licensing_url or "").strip()
        self._license_key = (license_key or "").strip()
        self._fingerprint_path = (fingerprint_path or "/var/lib/myapp/device_fingerprint").strip()
        self._http_timeout_seconds = float(http_timeout_seconds or 10.0)
        self._min_renew_seconds = int(min_renew_seconds or 30)
        self._post_json = post_json_func

        self._lock = threading.Lock()
        self._state = LicensingState(
            pro_enabled=False,
            last_ok_at=None,
            last_error=None,
            session_token=None,
        )
        self._expires_in = 0

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._fingerprint: Optional[str] = None

    @staticmethod
    def from_env() -> "LicensingManager":
        licensing_url = (os.getenv("LICENSING_URL") or "").strip()
        license_key = (os.getenv("LICENSE_KEY") or "").strip()
        fingerprint_path = (os.getenv("FINGERPRINT_PATH") or "/var/lib/myapp/device_fingerprint").strip()

        def _env_int(name: str, default: int) -> int:
            raw = os.getenv(name)
            if raw is None or raw.strip() == "":
                return default
            try:
                return int(raw.strip())
            except Exception:
                return default

        def _env_float(name: str, default: float) -> float:
            raw = os.getenv(name)
            if raw is None or raw.strip() == "":
                return default
            try:
                return float(raw.strip())
            except Exception:
                return default

        timeout = _env_float("LICENSING_HTTP_TIMEOUT_SECONDS", 10.0)
        min_renew = _env_int("LICENSING_MIN_RENEW_SECONDS", 30)
        if min_renew < 1:
            min_renew = 1

        return LicensingManager(
            licensing_url=licensing_url,
            license_key=license_key,
            fingerprint_path=fingerprint_path,
            http_timeout_seconds=timeout,
            min_renew_seconds=min_renew,
        )

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()

        # Startup flow (sync): if no LICENSE_KEY => CORE; else /activate.
        self._startup_activate()

        # No point in running a renewal loop without enough config.
        if not self._license_key or not self._licensing_url:
            return

        t = threading.Thread(target=self._run, name="licensing-renewal", daemon=True)
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

        # Best-effort deactivate if we have enough context; ignore errors.
        try:
            fp = self._fingerprint or get_or_create_fingerprint(self._fingerprint_path)
            if self._licensing_url and self._license_key and fp:
                self._post_json(
                    _endpoint(self._licensing_url, "/v1/deactivate"),
                    {"license_key": self._license_key, "fingerprint": fp},
                    self._http_timeout_seconds,
                )
        except Exception:
            pass

    def is_pro_enabled(self) -> bool:
        with self._lock:
            return bool(self._state.pro_enabled)

    def get_state(self) -> LicensingState:
        with self._lock:
            return replace(self._state)

    def _set_state(self, *, pro_enabled: bool, last_ok_at: Optional[datetime], last_error: Optional[str], session_token: Optional[str]) -> None:
        with self._lock:
            self._state = LicensingState(
                pro_enabled=bool(pro_enabled),
                last_ok_at=last_ok_at,
                last_error=last_error,
                session_token=session_token,
            )

    def _utc_now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _startup_activate(self) -> None:
        if not self._license_key:
            self._set_state(pro_enabled=False, last_ok_at=None, last_error=None, session_token=None)
            return
        if not self._licensing_url:
            self._set_state(
                pro_enabled=False,
                last_ok_at=None,
                last_error="LICENSING_URL missing (LICENSE_KEY present)",
                session_token=None,
            )
            return

        try:
            fp = get_or_create_fingerprint(self._fingerprint_path)
            self._fingerprint = fp
            data = _request_or_raise(
                url=_endpoint(self._licensing_url, "/v1/activate"),
                payload={"license_key": self._license_key, "fingerprint": fp},
                timeout=self._http_timeout_seconds,
                post_json_func=self._post_json,
            )
            token = str(data.get("session_token") or "") or None
            expires_in = int(data.get("expires_in") or 0)
            plan = str(data.get("plan") or "").strip().lower()
            if plan != "pro":
                raise LicensingClientError("200: not_pro_plan", status_code=200, data=data)
            self._expires_in = max(0, expires_in)
            self._set_state(pro_enabled=True, last_ok_at=self._utc_now(), last_error=None, session_token=token)
        except Exception as exc:
            self._expires_in = 0
            if isinstance(exc, LicensingClientError):
                err = f"http_{exc.status_code}" if exc.status_code else "network_error"
            else:
                err = exc.__class__.__name__
            self._set_state(pro_enabled=False, last_ok_at=None, last_error=err, session_token=None)

    def _renew_in_seconds(self) -> int:
        exp = int(self._expires_in or 0)
        if exp <= 0:
            return max(1, int(self._min_renew_seconds))
        target = int(exp * 0.8)
        return max(int(self._min_renew_seconds), max(1, target))

    def _run(self) -> None:
        while not self._stop.is_set():
            sleep_s = self._renew_in_seconds()
            if self._stop.wait(timeout=float(sleep_s)):
                return

            if not self._license_key or not self._licensing_url:
                self._set_state(pro_enabled=False, last_ok_at=None, last_error=None, session_token=None)
                continue

            # If PRO is OFF, attempt to activate again; if ON, validate/renew.
            try:
                fp = self._fingerprint or get_or_create_fingerprint(self._fingerprint_path)
                self._fingerprint = fp
                path = "/v1/validate" if self.is_pro_enabled() else "/v1/activate"
                data = _request_or_raise(
                    url=_endpoint(self._licensing_url, path),
                    payload={"license_key": self._license_key, "fingerprint": fp},
                    timeout=self._http_timeout_seconds,
                    post_json_func=self._post_json,
                )
                token = str(data.get("session_token") or "") or None
                expires_in = int(data.get("expires_in") or 0)
                plan = str(data.get("plan") or "").strip().lower()
                if plan != "pro":
                    raise LicensingClientError("200: not_pro_plan", status_code=200, data=data)
                self._expires_in = max(0, expires_in)
                self._set_state(pro_enabled=True, last_ok_at=self._utc_now(), last_error=None, session_token=token)
            except Exception as exc:
                self._expires_in = 0
                # Simple policy: PRO OFF on any failure.
                if isinstance(exc, LicensingClientError):
                    err = f"http_{exc.status_code}" if exc.status_code else "network_error"
                else:
                    err = exc.__class__.__name__
                self._set_state(
                    pro_enabled=False,
                    last_ok_at=self.get_state().last_ok_at,
                    last_error=err,
                    session_token=None,
                )


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
