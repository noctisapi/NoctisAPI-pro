"""Tests for license telemetry: send_event, adaptive backoff, reuse_limit_exceeded
persistence, grace_expired detection, rollback_detected reporting."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from honey_licensing.online_client import LicenseEventRequest, OnlineLicenseClient
from app.license_online import (
    OnlineLicenseManager,
    _STATUS_ACTIVE,
    _STATUS_NETWORK_ERROR,
    _STATUS_REVOKED,
    _STATUS_EXPIRED,
    _STATUS_SUSPENDED,
    _STATUS_UNKNOWN,
    _utc_now_iso,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(base_url: str = "http://localhost:9999") -> OnlineLicenseClient:
    return OnlineLicenseClient(
        base_url=base_url,
        shared_secret="test-secret",
        timeout_seconds=5.0,
        max_retries=0,
        retry_backoff_seconds=0.0,
    )


def _make_manager(
    tmp_dir: str,
    *,
    check_interval: int = 3600,
    grace_period: int = 86400,
    initial_state: Optional[Dict[str, Any]] = None,
    get_offline_snapshot_fn=None,
) -> OnlineLicenseManager:
    state_path = os.path.join(tmp_dir, "online_state.json")
    if initial_state is not None:
        with open(state_path, "w") as f:
            json.dump(initial_state, f)
    client = _make_client()
    mgr = OnlineLicenseManager(
        client=client,
        state_path=state_path,
        check_interval_seconds=check_interval,
        grace_period_seconds=grace_period,
        product="noctisapi",
        app_version="0.1.0",
        get_license_id_fn=lambda: "lic-test",
        get_instance_id_fn=lambda: "inst-test",
        get_offline_snapshot_fn=get_offline_snapshot_fn,
    )
    return mgr


# ===========================================================================
# 1. send_event — OnlineLicenseClient
# ===========================================================================

class SendEventTests(unittest.TestCase):

    def test_send_event_success_returns_true(self):
        client = _make_client()
        import httpx
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200

        with patch("httpx.Client") as mock_cls:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.post = MagicMock(return_value=mock_resp)
            mock_cls.return_value = mock_http

            req = LicenseEventRequest(
                license_id="lic-1",
                instance_id="inst-1",
                event="startup",
                product="noctisapi",
                version="0.1.0",
            )
            result = client.send_event(req)

        self.assertTrue(result)
        call_kwargs = mock_http.post.call_args
        self.assertIn("/v1/licenses/event", call_kwargs[0][0])

    def test_send_event_non_200_returns_false(self):
        client = _make_client()
        import httpx
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 401

        with patch("httpx.Client") as mock_cls:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.post = MagicMock(return_value=mock_resp)
            mock_cls.return_value = mock_http

            req = LicenseEventRequest(
                license_id="lic-1",
                instance_id="inst-1",
                event="startup",
                product="noctisapi",
                version="0.1.0",
            )
            result = client.send_event(req)

        self.assertFalse(result)

    def test_send_event_network_error_returns_false(self):
        client = _make_client()
        import httpx

        with patch("httpx.Client") as mock_cls:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.post = MagicMock(side_effect=httpx.ConnectError("refused"))
            mock_cls.return_value = mock_http

            req = LicenseEventRequest(
                license_id="lic-1",
                instance_id="inst-1",
                event="startup",
                product="noctisapi",
                version="0.1.0",
            )
            result = client.send_event(req)

        self.assertFalse(result)

    def test_send_event_uses_shared_secret_header(self):
        client = OnlineLicenseClient(
            base_url="http://localhost:9999",
            shared_secret="mysecret",
            timeout_seconds=5.0,
            max_retries=0,
            retry_backoff_seconds=0.0,
        )
        import httpx
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200

        with patch("httpx.Client") as mock_cls:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.post = MagicMock(return_value=mock_resp)
            mock_cls.return_value = mock_http

            req = LicenseEventRequest(
                license_id="lic-1",
                instance_id="inst-1",
                event="grace_expired",
                product="noctisapi",
                version="0.1.0",
                extra={"grace_expired_at": "2026-03-20T10:00:00Z"},
            )
            client.send_event(req)

        _, call_kwargs = mock_http.post.call_args
        headers = call_kwargs.get("headers", {})
        self.assertEqual(headers.get("X-License-Check-Token"), "mysecret")

    def test_send_event_includes_extra_fields(self):
        client = _make_client()
        import httpx
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200

        with patch("httpx.Client") as mock_cls:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.post = MagicMock(return_value=mock_resp)
            mock_cls.return_value = mock_http

            req = LicenseEventRequest(
                license_id="lic-1",
                instance_id="inst-1",
                event="rollback_detected",
                product="noctisapi",
                version="0.1.0",
                extra={"attempted_version": 2},
            )
            client.send_event(req)

        _, call_kwargs = mock_http.post.call_args
        body = call_kwargs.get("json", {})
        self.assertEqual(body.get("attempted_version"), 2)


# ===========================================================================
# 2. Startup event — fired from start()
# ===========================================================================

class StartupEventTests(unittest.TestCase):

    def test_startup_event_attempted_on_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            sent_events = []

            def mock_check(req):
                from honey_licensing.online_client import LicenseCheckResponse
                return LicenseCheckResponse(status="active")

            def mock_send_event(req):
                sent_events.append(req.event)
                return True

            mgr = _make_manager(tmp, check_interval=3600, grace_period=86400)
            mgr._client.check = mock_check
            mgr._client.send_event = mock_send_event

            mgr.start()
            mgr.stop()

            # Give the daemon thread a moment to fire
            time.sleep(0.1)
            self.assertIn("startup", sent_events)

    def test_startup_continues_when_event_fails(self):
        """If send_event raises or returns False, start() must still complete."""
        with tempfile.TemporaryDirectory() as tmp:
            def mock_check(req):
                from honey_licensing.online_client import LicenseCheckResponse
                return LicenseCheckResponse(status="active")

            def mock_send_event(req):
                raise RuntimeError("simulated event failure")

            mgr = _make_manager(tmp, check_interval=3600, grace_period=86400)
            mgr._client.check = mock_check
            mgr._client.send_event = mock_send_event

            # Must not raise
            mgr.start()
            mgr.stop()
            self.assertTrue(mgr.is_online_allowed())


# ===========================================================================
# 3. Adaptive backoff
# ===========================================================================

class AdaptiveBackoffTests(unittest.TestCase):

    def test_network_error_uses_shorter_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                check_interval=14400,
                initial_state={
                    "license_id": "lic-1",
                    "online_status": _STATUS_NETWORK_ERROR,
                    "grace_deadline": None,
                },
            )
            interval = mgr._effective_check_interval()
        # Should be much less than 14400 (max 900 = 15min)
        self.assertLessEqual(interval, 900)
        self.assertGreaterEqual(interval, 60)

    def test_active_uses_full_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                check_interval=14400,
                initial_state={
                    "license_id": "lic-1",
                    "online_status": _STATUS_ACTIVE,
                    "grace_deadline": None,
                },
            )
            interval = mgr._effective_check_interval()
        self.assertEqual(interval, 14400)

    def test_revoked_uses_full_interval(self):
        """Terminal states do not get fast retry — they require admin action."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                check_interval=14400,
                initial_state={
                    "license_id": "lic-1",
                    "online_status": _STATUS_REVOKED,
                    "grace_deadline": None,
                },
            )
            interval = mgr._effective_check_interval()
        self.assertEqual(interval, 14400)

    def test_expired_uses_full_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                check_interval=7200,
                initial_state={
                    "license_id": "lic-1",
                    "online_status": _STATUS_EXPIRED,
                    "grace_deadline": None,
                },
            )
            self.assertEqual(mgr._effective_check_interval(), 7200)

    def test_suspended_uses_full_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                check_interval=7200,
                initial_state={
                    "license_id": "lic-1",
                    "online_status": _STATUS_SUSPENDED,
                    "grace_deadline": None,
                },
            )
            self.assertEqual(mgr._effective_check_interval(), 7200)

    def test_reuse_limit_exceeded_uses_full_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                check_interval=7200,
                initial_state={
                    "license_id": "lic-1",
                    "online_status": "reuse_limit_exceeded",
                    "grace_deadline": None,
                },
            )
            self.assertEqual(mgr._effective_check_interval(), 7200)

    def test_unknown_uses_full_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(tmp, check_interval=3600)
            self.assertEqual(mgr._effective_check_interval(), 3600)

    def test_network_error_interval_respects_minimum_900(self):
        """Even with check_interval=60, network_error returns 900 minimum."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                check_interval=60,
                initial_state={
                    "license_id": "lic-1",
                    "online_status": _STATUS_NETWORK_ERROR,
                    "grace_deadline": None,
                },
            )
            self.assertEqual(mgr._effective_check_interval(), 900)


# ===========================================================================
# 4. reuse_limit_exceeded — must persist after restart
# ===========================================================================

class ReuseExceededPersistenceTests(unittest.TestCase):

    def test_reuse_limit_exceeded_is_persisted(self):
        """State file must be written even when status is reuse_limit_exceeded."""
        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "state.json")
            client = _make_client()
            mgr = OnlineLicenseManager(
                client=client,
                state_path=state_path,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
                product="noctisapi",
                app_version="0.1.0",
                get_license_id_fn=lambda: "lic-test",
                get_instance_id_fn=lambda: "inst-test",
            )
            mgr._apply_check_result(license_id="lic-test", status="reuse_limit_exceeded")

            self.assertTrue(os.path.exists(state_path), "state file must be written")
            with open(state_path) as f:
                saved = json.load(f)
            self.assertEqual(saved["online_status"], "reuse_limit_exceeded")

    def test_reuse_limit_exceeded_survives_reload(self):
        """A fresh manager loaded from the persisted state must deny PRO."""
        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "state.json")

            # First manager: receives reuse_limit_exceeded and saves it
            client = _make_client()
            mgr1 = OnlineLicenseManager(
                client=client,
                state_path=state_path,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
                product="noctisapi",
                app_version="0.1.0",
                get_license_id_fn=lambda: "lic-test",
                get_instance_id_fn=lambda: "inst-test",
            )
            mgr1._apply_check_result(license_id="lic-test", status="reuse_limit_exceeded")
            self.assertFalse(mgr1.is_online_allowed())

            # Simulated restart: second manager loads from the same state file
            mgr2 = OnlineLicenseManager(
                client=_make_client(),
                state_path=state_path,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
                product="noctisapi",
                app_version="0.1.0",
                get_license_id_fn=lambda: "lic-test",
                get_instance_id_fn=lambda: "inst-test",
            )
            self.assertFalse(mgr2.is_online_allowed(), "reuse_limit_exceeded must survive restart")


# ===========================================================================
# 5. grace_expired event emitted on reconnection
# ===========================================================================

class GraceExpiredEventTests(unittest.TestCase):

    def _past_deadline(self, seconds_ago: int = 3600) -> str:
        dt = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _future_deadline(self, seconds_from_now: int = 3600) -> str:
        dt = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def test_grace_expired_event_emitted_on_recovery(self):
        """When reconnecting after an expired grace, grace_expired event is sent."""
        with tempfile.TemporaryDirectory() as tmp:
            sent_events: list = []

            state_path = os.path.join(tmp, "state.json")
            expired_deadline = self._past_deadline(3600)
            initial_state = {
                "license_id": "lic-1",
                "online_status": _STATUS_NETWORK_ERROR,
                "grace_deadline": expired_deadline,
                "last_checked_at": None,
                "last_online_at": None,
                "reason": "check_failed:timeout",
            }
            with open(state_path, "w") as f:
                json.dump(initial_state, f)

            mgr = OnlineLicenseManager(
                client=_make_client(),
                state_path=state_path,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
                product="noctisapi",
                app_version="0.1.0",
                get_license_id_fn=lambda: "lic-1",
                get_instance_id_fn=lambda: "inst-1",
            )
            # Intercept _send_telemetry_event
            original_send = mgr._send_telemetry_event
            def capture_send(event, extra):
                sent_events.append((event, extra))
                return True
            mgr._send_telemetry_event = capture_send

            # Simulate recovery: server responds active
            mgr._apply_check_result(license_id="lic-1", status="active")

            # Give daemon thread a moment (in this case synchronous capture)
            time.sleep(0.05)

            grace_events = [e for e in sent_events if e[0] == "grace_expired"]
            self.assertEqual(len(grace_events), 1)
            _, extra = grace_events[0]
            self.assertEqual(extra["grace_expired_at"], expired_deadline)
            self.assertEqual(extra["last_known_online_status"], _STATUS_NETWORK_ERROR)

    def test_no_grace_expired_event_when_grace_not_expired(self):
        """If the grace deadline is still in the future, no grace_expired event."""
        with tempfile.TemporaryDirectory() as tmp:
            sent_events: list = []

            state_path = os.path.join(tmp, "state.json")
            future_deadline = self._future_deadline(3600)
            initial_state = {
                "license_id": "lic-1",
                "online_status": _STATUS_NETWORK_ERROR,
                "grace_deadline": future_deadline,
                "last_checked_at": None,
                "last_online_at": None,
                "reason": None,
            }
            with open(state_path, "w") as f:
                json.dump(initial_state, f)

            mgr = OnlineLicenseManager(
                client=_make_client(),
                state_path=state_path,
                check_interval_seconds=3600,
                grace_period_seconds=86400,
                product="noctisapi",
                app_version="0.1.0",
                get_license_id_fn=lambda: "lic-1",
                get_instance_id_fn=lambda: "inst-1",
            )

            def capture_send(event, extra):
                sent_events.append((event, extra))
                return True
            mgr._send_telemetry_event = capture_send

            mgr._apply_check_result(license_id="lic-1", status="active")
            time.sleep(0.05)

            grace_events = [e for e in sent_events if e[0] == "grace_expired"]
            self.assertEqual(len(grace_events), 0)

    def test_no_grace_expired_event_when_no_deadline(self):
        """If there was no grace period at all, no event."""
        with tempfile.TemporaryDirectory() as tmp:
            sent_events: list = []
            mgr = _make_manager(tmp, initial_state={
                "license_id": "lic-1",
                "online_status": _STATUS_ACTIVE,
                "grace_deadline": None,
                "last_checked_at": None,
                "last_online_at": None,
                "reason": None,
            })

            def capture_send(event, extra):
                sent_events.append((event, extra))
                return True
            mgr._send_telemetry_event = capture_send

            mgr._apply_check_result(license_id="lic-1", status="active")
            time.sleep(0.05)

            self.assertEqual(sent_events, [])


# ===========================================================================
# 6. rollback_detected — best-effort event reported once per generation
# ===========================================================================

class RollbackDetectedEventTests(unittest.TestCase):

    def _snapshot_rollback(self, attempted_gen: int = 2) -> Dict[str, Any]:
        return {
            "reason_code": "ROLLBACK_DETECTED",
            "license_generation": attempted_gen,
            "license_id": "lic-rb",
            "pro_enabled": False,
        }

    def test_rollback_event_sent_when_detected(self):
        sent_events: list = []

        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self._snapshot_rollback(attempted_gen=2)
            mgr = _make_manager(tmp, get_offline_snapshot_fn=lambda: snapshot)

            def capture_send(event, extra):
                sent_events.append((event, dict(extra)))
                return True
            mgr._send_telemetry_event = capture_send

            mgr._check_and_report_rollback()

        self.assertEqual(len(sent_events), 1)
        self.assertEqual(sent_events[0][0], "rollback_detected")
        self.assertEqual(sent_events[0][1].get("attempted_version"), 2)

    def test_rollback_not_reported_twice_for_same_generation(self):
        sent_events: list = []

        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self._snapshot_rollback(attempted_gen=2)
            mgr = _make_manager(tmp, get_offline_snapshot_fn=lambda: snapshot)

            def capture_send(event, extra):
                sent_events.append(event)
                return True
            mgr._send_telemetry_event = capture_send

            mgr._check_and_report_rollback()
            mgr._check_and_report_rollback()
            mgr._check_and_report_rollback()

        self.assertEqual(len(sent_events), 1, "must report only once per generation")

    def test_rollback_reported_again_for_new_generation(self):
        """If the generation changes (e.g. another tamper attempt), report again."""
        sent_events: list = []
        current_gen = {"gen": 2}

        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(
                tmp,
                get_offline_snapshot_fn=lambda: self._snapshot_rollback(current_gen["gen"]),
            )

            def capture_send(event, extra):
                sent_events.append((event, dict(extra)))
                return True
            mgr._send_telemetry_event = capture_send

            mgr._check_and_report_rollback()
            self.assertEqual(len(sent_events), 1)

            current_gen["gen"] = 3  # new tamper attempt with a different generation
            mgr._check_and_report_rollback()
            self.assertEqual(len(sent_events), 2)

    def test_no_rollback_event_when_snapshot_ok(self):
        sent_events: list = []

        with tempfile.TemporaryDirectory() as tmp:
            snapshot = {"reason_code": "OK", "license_generation": 5, "license_id": "lic-ok"}
            mgr = _make_manager(tmp, get_offline_snapshot_fn=lambda: snapshot)

            def capture_send(event, extra):
                sent_events.append(event)
                return True
            mgr._send_telemetry_event = capture_send

            mgr._check_and_report_rollback()

        self.assertEqual(sent_events, [])

    def test_rollback_no_event_without_snapshot_fn(self):
        """When get_offline_snapshot_fn is None, _check_and_report_rollback is a no-op."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = _make_manager(tmp, get_offline_snapshot_fn=None)
            # Must not raise
            mgr._check_and_report_rollback()

    def test_rollback_event_failure_does_not_affect_enforcement(self):
        """Even if event sending fails, rollback detection is still LOCAL and correct."""
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self._snapshot_rollback(attempted_gen=2)
            mgr = _make_manager(tmp, get_offline_snapshot_fn=lambda: snapshot)
            mgr._send_telemetry_event = lambda event, extra: False  # always fails

            # Must not raise; local state is unaffected
            mgr._check_and_report_rollback()
            # last_rollback_reported_gen should NOT be updated when event failed
            self.assertIsNone(mgr._last_rollback_reported_gen)


if __name__ == "__main__":
    unittest.main()
