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

from honey_licensing.online_client import (
    LicenseCheckRequest,
    LicenseEventRequest,
    LicenseSyncRequest,
    OnlineCheckError,
    OnlineLicenseClient,
)
from honey_licensing.offline_license import LicenseVerifier, load_public_key_pem
from honey_licensing.product import PRODUCT_ID as _PRODUCT_ID

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
        get_client_tier_fn: Optional[Callable[[], Optional[str]]] = None,
        license_path: Optional[str] = None,
        get_local_generation_fn: Optional[Callable[[], int]] = None,
        on_new_license_fn: Optional[Callable[[], None]] = None,
        get_offline_snapshot_fn: Optional[Callable[[], Dict[str, Any]]] = None,
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
        self._get_client_tier = get_client_tier_fn
        self._license_path = license_path
        self._get_local_generation = get_local_generation_fn
        self._on_new_license = on_new_license_fn
        self._get_offline_snapshot = get_offline_snapshot_fn

        self._lock = threading.Lock()
        self._state: Dict[str, Any] = self._load_state()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_rollback_reported_gen: Optional[int] = None

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

        # Fire startup event in a daemon thread — best-effort, must not delay startup
        threading.Thread(
            target=self._send_telemetry_event,
            args=("startup", {}),
            name="license-event-startup",
            daemon=True,
        ).start()

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
            interval = float(self._effective_check_interval())
            if self._stop.wait(timeout=interval):
                return
            self._run_check()

    def _effective_check_interval(self) -> int:
        """Return the check interval to use for the next sleep.

        Policy:
          - network_error → shorter interval (max(900, check_interval // 16), min 15 min)
            so the manager detects server recovery faster without busy-looping.
          - all other states (active, revoked, expired, suspended, unknown,
            reuse_limit_exceeded) → full configured interval.
            Terminal hard-deny states do NOT get an optimistic fast-retry because
            they require an explicit admin action to resolve, not connectivity.
        """
        with self._lock:
            status = str(self._state.get("online_status") or _STATUS_UNKNOWN).strip()
        if status == _STATUS_NETWORK_ERROR:
            return max(900, self._check_interval // 16)
        return self._check_interval

    def _run_check(self) -> None:
        # Best-effort rollback report before the network check so the server
        # gets the signal even if the check itself fails.
        try:
            self._check_and_report_rollback()
        except Exception:
            pass

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

        client_tier: Optional[str] = None
        if self._get_client_tier is not None:
            try:
                client_tier = self._get_client_tier()
            except Exception:
                pass

        req = LicenseCheckRequest(
            license_id=license_id,
            instance_id=instance_id,
            product=self._product,
            version=self._app_version,
            instance_fingerprint=instance_fingerprint,
            client_tier=client_tier,
        )

        try:
            resp = self._client.check(req)
            self._apply_check_result(license_id=license_id, status=resp.status)
            if resp.status == "reuse_limit_exceeded":
                logger.warning(
                    "license_online: REUSE LIMIT EXCEEDED license_id=%s instance_id=%s — "
                    "PRO features denied. Another instance may be using this license. "
                    "Contact support if this is unexpected.",
                    license_id,
                    instance_id,
                )
            else:
                logger.info(
                    "license_online: check ok license_id=%s status=%s",
                    license_id,
                    resp.status,
                )
                # If server has a newer license generation, pull the updated doc
                if resp.status == "active" and resp.license_generation is not None and self._license_path:
                    local_gen = 0
                    if self._get_local_generation is not None:
                        try:
                            local_gen = int(self._get_local_generation() or 0)
                        except Exception:
                            pass
                    if resp.license_generation > local_gen:
                        logger.info(
                            "license_online: server gen %d > local gen %d — triggering sync",
                            resp.license_generation, local_gen,
                        )
                        self._run_sync(license_id=license_id, instance_id=instance_id)
        except OnlineCheckError as exc:
            self._apply_check_error(license_id=license_id, error=str(exc))
            logger.warning(
                "license_online: check failed license_id=%s error=%s grace_allowed=%s",
                license_id,
                exc,
                self.is_online_allowed(),
            )

    def _apply_check_result(self, *, license_id: str, status: str) -> None:
        now_dt = datetime.now(timezone.utc)
        now = _utc_now_iso()

        # Detect grace-expired recovery: we had an active grace deadline that already passed
        # and we're now receiving a valid server response. Emit an event so the server has
        # an audit trail of how long this instance operated without confirmation.
        grace_expired_event: Optional[Dict[str, Any]] = None
        with self._lock:
            old_grace = self._state.get("grace_deadline")
            old_status = str(self._state.get("online_status") or "").strip()
        if old_grace and old_status in (_STATUS_NETWORK_ERROR, _STATUS_UNKNOWN):
            deadline_dt = _parse_iso(old_grace)
            if deadline_dt is not None and now_dt >= deadline_dt:
                grace_expired_event = {
                    "grace_expired_at": old_grace,
                    "last_known_online_status": old_status,
                }

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
        # Persist all statuses including reuse_limit_exceeded so restarts don't clear the block
        self._save_state(new_state)

        if grace_expired_event:
            threading.Thread(
                target=self._send_telemetry_event,
                args=("grace_expired", grace_expired_event),
                name="license-event-grace-expired",
                daemon=True,
            ).start()

    def _apply_check_error(self, *, license_id: str, error: str) -> None:
        now = _utc_now_iso()
        with self._lock:
            existing_grace = self._state.get("grace_deadline")
            last_online_at = self._state.get("last_online_at")

            if existing_grace is None:
                # Distinguish first-ever failure (no prior confirmed check) from
                # connectivity loss on a previously-validated instance.
                #
                # Without this, an attacker can block the licensing server from day 1
                # and receive the full grace period (default 3 days) of free Pro access.
                # HP_ONLINE_STARTUP_GRACE_SECONDS caps the window for a fresh instance
                # that has never reached the server. Default: 600 s (10 min).
                if last_online_at is None:
                    startup_grace_s = _env_int(
                        "HP_ONLINE_STARTUP_GRACE_SECONDS", default=600, min_val=0
                    )
                    effective_grace = min(startup_grace_s, self._grace_period)
                    logger.warning(
                        "license_online: first-ever check failed with no prior online history; "
                        "using startup grace of %ds (HP_ONLINE_STARTUP_GRACE_SECONDS). "
                        "Pro features will be denied after this window if the server remains unreachable.",
                        effective_grace,
                    )
                else:
                    effective_grace = self._grace_period

                deadline_dt = datetime.now(timezone.utc) + timedelta(seconds=effective_grace)
                grace_deadline: Optional[str] = (
                    deadline_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
                )
                logger.info(
                    "license_online: starting grace period deadline=%s grace_seconds=%d",
                    grace_deadline,
                    effective_grace,
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

    def _send_telemetry_event(self, event: str, extra: Dict[str, Any]) -> bool:
        """Send a best-effort telemetry event to the licensing server.

        Must not raise. Returns True on success. Called from daemon threads.
        """
        license_id = self._get_license_id()
        if not license_id:
            return False

        instance_id = self._get_instance_id()
        instance_fingerprint: Optional[str] = None
        if self._get_instance_fingerprint is not None:
            try:
                instance_fingerprint = self._get_instance_fingerprint()
            except Exception:
                pass

        client_tier: Optional[str] = None
        if self._get_client_tier is not None:
            try:
                client_tier = self._get_client_tier()
            except Exception:
                pass

        req = LicenseEventRequest(
            license_id=license_id,
            instance_id=instance_id,
            event=event,
            product=self._product,
            version=self._app_version,
            instance_fingerprint=instance_fingerprint,
            client_tier=client_tier,
            extra=extra or None,
        )
        try:
            ok = self._client.send_event(req)
        except Exception as exc:
            logger.debug("license_online: telemetry event=%s raised unexpectedly: %s", event, exc)
            return False
        if ok:
            logger.debug("license_online: telemetry event=%s sent ok", event)
        else:
            logger.debug("license_online: telemetry event=%s failed (best-effort)", event)
        return ok

    def _check_and_report_rollback(self) -> None:
        """Check the offline snapshot for a rollback and emit a best-effort event if found.

        Tracks the last reported attempted_generation so we don't re-send the same
        rollback event on every check cycle while the instance is stuck in that state.
        """
        if self._get_offline_snapshot is None:
            return
        try:
            snapshot = self._get_offline_snapshot()
        except Exception:
            return
        if snapshot.get("reason_code") != "ROLLBACK_DETECTED":
            return
        attempted_gen = int(snapshot.get("license_generation") or 0)
        with self._lock:
            last_reported = self._last_rollback_reported_gen
        if last_reported == attempted_gen:
            return  # already reported this generation
        extra: Dict[str, Any] = {"attempted_version": attempted_gen}
        license_id = str(snapshot.get("license_id") or "").strip()
        if not license_id:
            return
        logger.warning(
            "license_online: rollback_detected for license_id=%s attempted_gen=%d — reporting to server",
            license_id, attempted_gen,
        )
        sent = self._send_telemetry_event("rollback_detected", extra)
        if sent:
            with self._lock:
                self._last_rollback_reported_gen = attempted_gen

    def _run_sync(self, *, license_id: str, instance_id: str) -> None:
        """Pull a fresh signed license doc from the server and write it atomically.

        Only runs when the server advertises a higher license_generation than local.
        Validates the RSA signature before writing to prevent garbage writes.
        """
        if not self._license_path:
            return

        local_gen = 0
        if self._get_local_generation is not None:
            try:
                local_gen = int(self._get_local_generation() or 0)
            except Exception:
                pass

        instance_fingerprint: Optional[str] = None
        if self._get_instance_fingerprint is not None:
            try:
                instance_fingerprint = self._get_instance_fingerprint()
            except Exception:
                pass

        client_tier: Optional[str] = None
        if self._get_client_tier is not None:
            try:
                client_tier = self._get_client_tier()
            except Exception:
                pass

        sync_req = LicenseSyncRequest(
            license_id=license_id,
            instance_id=instance_id,
            product=self._product,
            version=self._app_version,
            local_generation=local_gen,
            instance_fingerprint=instance_fingerprint,
            client_tier=client_tier,
        )

        try:
            sync_resp = self._client.sync(sync_req)
        except OnlineCheckError as exc:
            logger.warning("license_online: sync request failed: %s", exc)
            return

        if sync_resp.status == "unchanged":
            logger.debug("license_online: sync — already at latest generation")
            return

        if sync_resp.status != "active" or sync_resp.license_doc is None:
            logger.warning(
                "license_online: sync returned status=%s reason=%s; no doc written",
                sync_resp.status, sync_resp.reason,
            )
            return

        # Validate signature before writing (prevents corrupt/tampered docs from disk)
        try:
            pub_pem = load_public_key_pem()
            verifier = LicenseVerifier(public_key_pem=pub_pem)
            ok, payload, sig_reason = verifier.verify(sync_resp.license_doc)
            if not ok:
                logger.warning(
                    "license_online: sync doc signature invalid (%s); refusing to write", sig_reason
                )
                return
        except Exception as exc:
            logger.warning("license_online: could not verify synced doc signature: %s; refusing to write", exc)
            return

        # Validate product — refuse to write a doc that would immediately cause LICENSE_PRODUCT_MISMATCH
        doc_product = str((payload or {}).get("product") or "").strip().lower()
        if doc_product != _PRODUCT_ID:
            logger.error(
                "license_online: sync doc product %r != expected %r; "
                "refusing to write — re-issue the license with app_id=%r",
                doc_product, _PRODUCT_ID, _PRODUCT_ID,
            )
            return

        # Atomic write
        path = self._license_path
        parent = os.path.dirname(path) or "."
        try:
            os.makedirs(parent, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix="license-sync-", suffix=".tmp", dir=parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(
                        sync_resp.license_doc, f,
                        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                    )
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
            logger.error("license_online: failed to write synced license to %s: %s", path, exc)
            return

        logger.info(
            "license_online: new license written gen=%s path=%s",
            sync_resp.license_generation, path,
        )
        if self._on_new_license is not None:
            try:
                self._on_new_license()
            except Exception as exc:
                logger.warning("license_online: on_new_license callback failed: %s", exc)

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
        get_client_tier_fn: Optional[Callable[[], Optional[str]]] = None,
        license_path: Optional[str] = None,
        get_local_generation_fn: Optional[Callable[[], int]] = None,
        on_new_license_fn: Optional[Callable[[], None]] = None,
        get_offline_snapshot_fn: Optional[Callable[[], Dict[str, Any]]] = None,
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
        product = _PRODUCT_ID  # Fixed at build time — never read from environment.
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
            get_client_tier_fn=get_client_tier_fn,
            license_path=license_path,
            get_local_generation_fn=get_local_generation_fn,
            on_new_license_fn=on_new_license_fn,
            get_offline_snapshot_fn=get_offline_snapshot_fn,
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
    get_client_tier_fn: Optional[Callable[[], Optional[str]]] = None,
    license_path: Optional[str] = None,
    get_local_generation_fn: Optional[Callable[[], int]] = None,
    on_new_license_fn: Optional[Callable[[], None]] = None,
    get_offline_snapshot_fn: Optional[Callable[[], Dict[str, Any]]] = None,
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
            get_client_tier_fn=get_client_tier_fn,
            license_path=license_path,
            get_local_generation_fn=get_local_generation_fn,
            on_new_license_fn=on_new_license_fn,
            get_offline_snapshot_fn=get_offline_snapshot_fn,
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
