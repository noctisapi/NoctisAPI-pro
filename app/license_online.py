"""Online license validation manager.

Runs periodic heartbeat checks against the licensing server and applies the grace
period policy to determine whether PRO features are permitted when the server is
temporarily unreachable.

State machine (per check cycle):
  offline invalid                            => gate never asked (pro_license handles this)
  online check -> active                     => PRO_ACTIVE  (is_online_allowed=True)
  online check -> revoked/expired/suspended  => PRO_OFF     (is_online_allowed=False)
  online check -> network/timeout/5xx        => grace period starts (or continues)
    within grace deadline                    => PRO_GRACE   (is_online_allowed=True)
    grace deadline exceeded                  => PRO_OFF     (is_online_allowed=False)

Configuration (env vars):
  HP_LICENSING_SERVER_URL           Required to enable online checks
  HP_ONLINE_CHECK_SECRET            Required shared secret matching ONLINE_CHECK_SECRET on server
  HP_ONLINE_CHECK_INTERVAL_SECONDS  Check interval (default: 14400 = 4 hours, min: 60)
  HP_ONLINE_GRACE_PERIOD_SECONDS    Grace on connectivity loss (default: 259200 = 3 days)
  HP_ONLINE_LICENSE_STATE_PATH      Where to persist online state (default: /var/lib/myapp/online_license_state.json)

The manager is a singleton. Call init_manager() once at startup, then use
is_online_allowed() as a gate in pro_license.py.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

from honey_licensing.online_client import LicenseCheckRequest, OnlineCheckError, OnlineLicenseClient

logger = logging.getLogger(__name__)

# Status constants stored in the state file
_STATUS_ACTIVE = "active"
_STATUS_REVOKED = "revoked"
_STATUS_EXPIRED = "expired"
_STATUS_SUSPENDED = "suspended"
_STATUS_UNKNOWN = "unknown"           # Initial state / no check done yet
_STATUS_NETWORK_ERROR = "network_error"  # Last check failed with connectivity issue

_TERMINAL_STATUSES = frozenset((_STATUS_REVOKED, _STATUS_EXPIRED, _STATUS_SUSPENDED, "reuse_limit_exceeded"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env_int(name: str, default: int, min_val: int = 0) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return max(min_val, int(raw))
    except (ValueError, TypeError):
        return default


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class OnlineLicenseManager:
    """Manages periodic online license validation against the licensing server.

    Persists state to a JSON file (HP_ONLINE_LICENSE_STATE_PATH) so grace period
    accounting survives process restarts.

    Thread-safe. The background thread runs check_interval_seconds apart after
    an immediate check on start().
    """

    def __init__(
        self,
        *,
        client: OnlineLicenseClient,
        state_path: str,
        check_interval_seconds: int,
        grace_period_seconds: int,
        product: str,
        app_version: str,
        get_license_id_fn: Callable[[], Optional[str]],
        get_instance_id_fn: Callable[[], str],
        get_instance_fingerprint_fn: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        self._client = client
        self._state_path = state_path
        self._check_interval = max(60, int(check_interval_seconds))
        self._grace_period = max(0, int(grace_period_seconds))
        self._product = product
        self._app_version = app_version
        self._get_license_id = get_license_id_fn
        self._get_instance_id = get_instance_id_fn
        self._get_instance_fingerprint = get_instance_fingerprint_fn

        self._lock = threading.Lock()
        self._state: Dict[str, Any] = self._load_state()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -------------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """Start the manager: immediate check, then background periodic loop."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()

        # Run once immediately (blocking) so the app has a fresh result at startup
        self._run_check()

        t = threading.Thread(target=self._run_loop, name="license-online-recheck", daemon=True)
        with self._lock:
            self._thread = t
        t.start()

        logger.info(
            "license_online: manager started interval=%ds grace=%ds state_path=%s",
            self._check_interval,
            self._grace_period,
            self._state_path,
        )

    def stop(self) -> None:
        """Stop the background thread gracefully."""
        self._stop.set()
        t: Optional[threading.Thread] = None
        with self._lock:
            t = self._thread
        if t and t.is_alive():
            t.join(timeout=5.0)

    def check_now(self) -> None:
        """Trigger an immediate online check (e.g. after a license upload)."""
        self._run_check()

    def is_online_allowed(self) -> bool:
        """Return True if the online state permits PRO features.

        True when:
          - status is "active"
          - status is "unknown" (startup, no check done yet)
          - status is "network_error" AND grace deadline has not passed

        False when:
          - status is "revoked", "expired", or "suspended"
          - status is "network_error" AND grace deadline has passed
        """
        with self._lock:
            state = dict(self._state)

        status = str(state.get("online_status") or _STATUS_UNKNOWN).strip()

        if status == _STATUS_ACTIVE:
            return True

        if status in _TERMINAL_STATUSES:
            return False

        # unknown or network_error: check grace period
        grace_deadline = state.get("grace_deadline")
        if not grace_deadline:
            # No grace deadline set yet — still in initial unknown state
            return True

        deadline_dt = _parse_iso(grace_deadline)
        if deadline_dt is None:
            logger.warning("license_online: unparseable grace_deadline=%r; denying PRO", grace_deadline)
            return False

        allowed = datetime.now(timezone.utc) < deadline_dt
        if not allowed:
            logger.warning(
                "license_online: grace period exhausted (deadline=%s); PRO features disabled",
                grace_deadline,
            )
        return allowed

    def get_online_state(self) -> Dict[str, Any]:
        """Return a copy of the current persisted online state."""
        with self._lock:
            return dict(self._state)

    # -------------------------------------------------------------------------
    # Internal: loop and check
    # -------------------------------------------------------------------------

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(timeout=float(self._check_interval)):
                return
            self._run_check()

    def _run_check(self) -> None:
        license_id = self._get_license_id()
        if not license_id:
            logger.debug("license_online: no license_id available; skipping check")
            return

        instance_id = self._get_instance_id()
        instance_fingerprint: Optional[str] = None
        if self._get_instance_fingerprint is not None:
            try:
                instance_fingerprint = self._get_instance_fingerprint()
            except Exception:
                pass
        req = LicenseCheckRequest(
            license_id=license_id,
            instance_id=instance_id,
            product=self._product,
            version=self._app_version,
            instance_fingerprint=instance_fingerprint,
        )

        try:
            resp = self._client.check(req)
            self._apply_check_result(license_id=license_id, status=resp.status)
            logger.info(
                "license_online: check ok license_id=%s status=%s",
                license_id,
                resp.status,
            )
        except OnlineCheckError as exc:
            self._apply_check_error(license_id=license_id, error=str(exc))
            logger.warning(
                "license_online: check failed license_id=%s error=%s grace_allowed=%s",
                license_id,
                exc,
                self.is_online_allowed(),
            )

    def _apply_check_result(self, *, license_id: str, status: str) -> None:
        now = _utc_now_iso()
        with self._lock:
            new_state: Dict[str, Any] = {
                "license_id": license_id,
                "online_status": status,
                "last_checked_at": now,
                "last_online_at": now if status == _STATUS_ACTIVE else self._state.get("last_online_at"),
                # Clear grace deadline on any successful server response
                "grace_deadline": None,
                "reason": None if status == _STATUS_ACTIVE else f"server_returned_{status}",
            }
            self._state = new_state
        # reuse_limit_exceeded is transient — don't persist it so a restart doesn't stay blocked
        if status != "reuse_limit_exceeded":
            self._save_state(new_state)

    def _apply_check_error(self, *, license_id: str, error: str) -> None:
        now = _utc_now_iso()
        with self._lock:
            existing_grace = self._state.get("grace_deadline")

            if existing_grace is None:
                # First error: start grace countdown from now
                deadline_dt = datetime.now(timezone.utc) + timedelta(seconds=self._grace_period)
                grace_deadline: Optional[str] = (
                    deadline_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
                )
                logger.info(
                    "license_online: starting grace period deadline=%s grace_seconds=%d",
                    grace_deadline,
                    self._grace_period,
                )
            else:
                # Keep original deadline — do NOT extend on repeated failures
                grace_deadline = existing_grace

            new_state: Dict[str, Any] = {
                "license_id": license_id,
                "online_status": _STATUS_NETWORK_ERROR,
                "last_checked_at": now,
                "last_online_at": self._state.get("last_online_at"),
                "grace_deadline": grace_deadline,
                "reason": f"check_failed:{error[:200]}",
            }
            self._state = new_state
        self._save_state(new_state)

    # -------------------------------------------------------------------------
    # State persistence
    # -------------------------------------------------------------------------

    def _load_state(self) -> Dict[str, Any]:
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                logger.debug("license_online: loaded persisted state from %s", self._state_path)
                return data
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("license_online: failed to load state from %s: %s", self._state_path, exc)
        return {
            "license_id": None,
            "online_status": _STATUS_UNKNOWN,
            "last_checked_at": None,
            "last_online_at": None,
            "grace_deadline": None,
            "reason": None,
        }

    def _save_state(self, state: Dict[str, Any]) -> None:
        path = self._state_path
        parent = os.path.dirname(path) or "."
        try:
            os.makedirs(parent, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix="license_online_state.", suffix=".tmp", dir=parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, path)
            except Exception:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
                raise
        except Exception as exc:
            logger.warning("license_online: failed to save state to %s: %s", path, exc)

    # -------------------------------------------------------------------------
    # Factory
    # -------------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        get_license_id_fn: Callable[[], Optional[str]],
        get_instance_id_fn: Callable[[], str],
        get_instance_fingerprint_fn: Optional[Callable[[], Optional[str]]] = None,
    ) -> Optional["OnlineLicenseManager"]:
        """Build from environment variables. Returns None if online checks are not configured."""
        client = OnlineLicenseClient.from_env()
        if client is None:
            return None

        state_path = (
            os.getenv("HP_ONLINE_LICENSE_STATE_PATH") or "/var/lib/myapp/online_license_state.json"
        ).strip()
        check_interval_seconds = _env_int("HP_ONLINE_CHECK_INTERVAL_SECONDS", 14400, min_val=60)
        grace_period_seconds = _env_int("HP_ONLINE_GRACE_PERIOD_SECONDS", 259200, min_val=0)
        product = (os.getenv("HP_PRODUCT") or "noctisapi").strip()
        app_version = (os.getenv("APP_VERSION") or os.getenv("HP_API_VERSION") or "").strip()

        return cls(
            client=client,
            state_path=state_path,
            check_interval_seconds=check_interval_seconds,
            grace_period_seconds=grace_period_seconds,
            product=product,
            app_version=app_version,
            get_license_id_fn=get_license_id_fn,
            get_instance_id_fn=get_instance_id_fn,
            get_instance_fingerprint_fn=get_instance_fingerprint_fn,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_MANAGER_LOCK = threading.Lock()
_MANAGER: Optional[OnlineLicenseManager] = None


def init_manager(
    *,
    get_license_id_fn: Callable[[], Optional[str]],
    get_instance_id_fn: Callable[[], str],
    get_instance_fingerprint_fn: Optional[Callable[[], Optional[str]]] = None,
) -> Optional[OnlineLicenseManager]:
    """Initialize the module singleton from env vars. Returns None if not configured.

    Safe to call multiple times — only initializes once.
    """
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is not None:
            return _MANAGER
        mgr = OnlineLicenseManager.from_env(
            get_license_id_fn=get_license_id_fn,
            get_instance_id_fn=get_instance_id_fn,
            get_instance_fingerprint_fn=get_instance_fingerprint_fn,
        )
        _MANAGER = mgr
        if mgr is None:
            logger.info(
                "license_online: HP_LICENSING_SERVER_URL not set; online checks disabled"
            )
        return mgr


def get_manager() -> Optional[OnlineLicenseManager]:
    """Return the singleton manager, or None if not configured."""
    with _MANAGER_LOCK:
        return _MANAGER


def is_online_allowed() -> bool:
    """Module-level gate used by pro_license.set_online_gate().

    Returns True when online checks are not configured (trust offline only),
    or when the manager's is_online_allowed() returns True.
    """
    mgr = get_manager()
    if mgr is None:
        return True  # Online checks not configured: offline-only mode
    return mgr.is_online_allowed()
