"""Tests for the SIEM security event logger."""
from __future__ import annotations

import io
import json
import os
import queue
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock as mock

# Make sure siem_logger can be imported regardless of test working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.siem_logger.event_schema import make_event
from app.siem_logger.json_formatter import to_json_line
from app.siem_logger import stdout_handler, file_handler, syslog_handler
from app.siem_logger import dispatcher


class TestEventSchema(unittest.TestCase):
    def _make(self, **kwargs):
        defaults = dict(
            kind="probe", source_ip="1.2.3.4", method="GET",
            endpoint="/api/v1/test", status_code=200,
            user_agent="curl/8.0", interaction_id="abc12345",
        )
        defaults.update(kwargs)
        return make_event(**defaults)

    def test_required_fields_present(self):
        ev = self._make()
        for field in ("timestamp", "event_type", "source_ip", "method",
                      "endpoint", "status_code", "user_agent",
                      "attack_type", "ttp", "interaction_id"):
            self.assertIn(field, ev, f"Missing field: {field}")

    def test_timestamp_iso8601_utc(self):
        ev = self._make()
        ts = ev["timestamp"]
        self.assertTrue(ts.endswith("Z"), f"Timestamp must end with Z: {ts}")
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_event_type_attack_on_4xx(self):
        ev = self._make(status_code=401)
        self.assertEqual(ev["event_type"], "api_attack")

    def test_event_type_interaction_on_2xx(self):
        ev = self._make(status_code=200)
        self.assertEqual(ev["event_type"], "api_interaction")

    def test_ttp_mapping_brute_force(self):
        ev = self._make(kind="unknown_token")
        self.assertEqual(ev["ttp"], "T1110")
        self.assertEqual(ev["attack_type"], "brute_force")

    def test_ttp_mapping_recon(self):
        ev = self._make(kind="recon_openapi")
        self.assertEqual(ev["ttp"], "T1592")

    def test_ttp_mapping_cloud_metadata(self):
        ev = self._make(kind="cloud_metadata")
        self.assertEqual(ev["ttp"], "T1552.005")

    def test_unknown_kind_defaults_to_recon(self):
        ev = self._make(kind="totally_unknown_kind")
        self.assertEqual(ev["ttp"], "T1595")

    def test_actor_id_optional_none(self):
        ev = self._make()
        self.assertIsNone(ev["actor_id"])

    def test_actor_id_set(self):
        ev = self._make(actor_id="deadbeef")
        self.assertEqual(ev["actor_id"], "deadbeef")

    def test_user_agent_truncated_to_400(self):
        ev = self._make(user_agent="A" * 500)
        self.assertEqual(len(ev["user_agent"]), 400)

    def test_method_uppercased(self):
        ev = self._make(method="get")
        self.assertEqual(ev["method"], "GET")

    def test_schema_is_stable(self):
        """Field names must not change between calls."""
        ev1 = self._make()
        ev2 = self._make(status_code=403, kind="token_used")
        self.assertEqual(set(ev1.keys()), set(ev2.keys()))


class TestJsonFormatter(unittest.TestCase):
    def test_single_line(self):
        ev = make_event(
            kind="probe", source_ip="1.2.3.4", method="GET",
            endpoint="/", status_code=200, user_agent="test",
            interaction_id="abc",
        )
        line = to_json_line(ev)
        self.assertEqual(line.count("\n"), 1)
        self.assertTrue(line.endswith("\n"))

    def test_valid_json(self):
        ev = make_event(
            kind="unknown_token", source_ip="10.0.0.1", method="POST",
            endpoint="/api/auth", status_code=401, user_agent="sqlmap",
            interaction_id="feed1234",
        )
        line = to_json_line(ev)
        parsed = json.loads(line.strip())
        self.assertIsInstance(parsed, dict)

    def test_deterministic(self):
        ev = make_event(
            kind="probe", source_ip="1.2.3.4", method="GET",
            endpoint="/", status_code=200, user_agent="ua",
            interaction_id="x",
        )
        line1 = to_json_line(ev)
        line2 = to_json_line(dict(ev))
        self.assertEqual(line1, line2)


class TestStdoutHandler(unittest.TestCase):
    def test_emits_to_stdout(self):
        captured = io.StringIO()
        with mock.patch("sys.stdout", captured):
            stdout_handler.emit('{"test":1}\n')
        self.assertIn('"test"', captured.getvalue())

    def test_never_raises(self):
        with mock.patch("sys.stdout", side_effect=OSError("broken pipe")):
            try:
                stdout_handler.emit("anything\n")
            except Exception as exc:
                self.fail(f"stdout_handler.emit raised: {exc}")


class TestFileHandler(unittest.TestCase):
    def test_creates_file_and_appends(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "subdir", "events.json")
            file_handler.configure(path)
            file_handler.emit('{"a":1}\n')
            file_handler.emit('{"b":2}\n')
            with open(path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0].strip()), {"a": 1})
            self.assertEqual(json.loads(lines[1].strip()), {"b": 2})

    def test_concurrent_writes_safe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "concurrent.json")
            file_handler.configure(path)
            errors = []

            def writer():
                for _ in range(50):
                    try:
                        file_handler.emit('{"x":1}\n')
                    except Exception as e:
                        errors.append(e)

            threads = [threading.Thread(target=writer) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(errors, [])
            with open(path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 500)

    def test_no_error_if_path_empty(self):
        file_handler.configure("")
        try:
            file_handler.emit("anything\n")
        except Exception as exc:
            self.fail(f"file_handler.emit raised with empty path: {exc}")


class TestSyslogHandler(unittest.TestCase):
    def test_rfc5424_format(self):
        syslog_handler.configure(
            enabled=True, host="127.0.0.1", port=9999,
            protocol="udp", facility_name="local0",
        )
        sent_packets = []

        class FakeSocket:
            def __init__(self, *a, **k): pass
            def settimeout(self, t): pass
            def sendto(self, data, addr): sent_packets.append((data, addr))
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with mock.patch("socket.socket", FakeSocket):
            syslog_handler.emit('{"event_type":"api_attack"}\n')

        self.assertEqual(len(sent_packets), 1)
        msg = sent_packets[0][0].decode("utf-8")
        # Must start with <PRI>1
        self.assertRegex(msg, r"^<\d+>1 ")
        # Must contain the JSON payload
        self.assertIn('"event_type"', msg)
        self.assertIn('"api_attack"', msg)
        # Must contain the app name
        self.assertIn("noctisapi", msg)

    def test_disabled_does_not_send(self):
        syslog_handler.configure(
            enabled=False, host="127.0.0.1", port=514,
            protocol="udp", facility_name="local0",
        )
        with mock.patch("socket.socket") as mock_sock:
            syslog_handler.emit('{"x":1}\n')
        mock_sock.assert_not_called()

    def test_network_failure_does_not_raise(self):
        syslog_handler.configure(
            enabled=True, host="192.0.2.1", port=514,
            protocol="udp", facility_name="local0",
        )
        with mock.patch("socket.socket", side_effect=OSError("network error")):
            try:
                syslog_handler.emit('{"x":1}\n')
            except Exception as exc:
                self.fail(f"syslog_handler.emit raised: {exc}")


class TestDispatcher(unittest.TestCase):
    def setUp(self):
        # Reset dispatcher state between tests
        dispatcher._started = False
        dispatcher._file_enabled = False
        dispatcher._syslog_enabled = False
        dispatcher._stdout_enabled = False
        dispatcher._q = queue.Queue(maxsize=dispatcher._QUEUE_MAX)
        # Reset file_handler path
        import app.siem_logger.file_handler as fh
        fh._path = ""
        # Reset syslog_handler
        import app.siem_logger.syslog_handler as sh
        sh._enabled = False

    def test_emit_event_reaches_stdout(self):
        captured = io.StringIO()
        with mock.patch("sys.stdout", captured):
            with mock.patch.dict(os.environ, {
                "SECURITY_EVENT_STDOUT": "true",
                "SECURITY_EVENT_FILE_ENABLED": "false",
            }):
                dispatcher.configure()
                dispatcher.emit_event(
                    kind="unknown_token",
                    source_ip="1.2.3.4",
                    method="POST",
                    endpoint="/api/auth",
                    status_code=401,
                    user_agent="sqlmap/1.0",
                    interaction_id="deadbeef",
                    actor_id="abc123",
                )
                dispatcher.shutdown()
        output = captured.getvalue()
        self.assertTrue(len(output) > 0)
        parsed = json.loads(output.strip().splitlines()[-1])
        self.assertEqual(parsed["source_ip"], "1.2.3.4")
        self.assertEqual(parsed["ttp"], "T1110")

    def test_emit_event_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "siem.json")
            with mock.patch.dict(os.environ, {
                "SECURITY_EVENT_STDOUT": "false",
                "SECURITY_EVENT_FILE_ENABLED": "true",
                "SECURITY_EVENT_FILE_PATH": path,
            }):
                dispatcher.configure()
                dispatcher.emit_event(
                    kind="probe",
                    source_ip="10.0.0.1",
                    method="GET",
                    endpoint="/api/users",
                    status_code=200,
                    user_agent="python-requests/2.28",
                    interaction_id="cafebabe",
                )
                dispatcher.shutdown()
            with open(path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 1)
            ev = json.loads(lines[0])
            self.assertEqual(ev["source_ip"], "10.0.0.1")

    def test_backpressure_does_not_block(self):
        """Full queue must drop silently, never block the caller."""
        dispatcher._q = queue.Queue(maxsize=2)
        # Fill queue without starting worker
        for _ in range(10):
            dispatcher.emit_event(
                kind="probe", source_ip="1.1.1.1", method="GET",
                endpoint="/", status_code=200, user_agent="bot",
                interaction_id="x",
            )
        # No exception, no hang

    def test_event_integrity_across_outputs(self):
        """Same JSON must be written to stdout and file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "integrity.json")
            captured = io.StringIO()
            with mock.patch("sys.stdout", captured):
                with mock.patch.dict(os.environ, {
                    "SECURITY_EVENT_STDOUT": "true",
                    "SECURITY_EVENT_FILE_ENABLED": "true",
                    "SECURITY_EVENT_FILE_PATH": path,
                }):
                    dispatcher.configure()
                    dispatcher.emit_event(
                        kind="recon_openapi",
                        source_ip="5.5.5.5",
                        method="GET",
                        endpoint="/openapi.json",
                        status_code=200,
                        user_agent="Scanner/1.0",
                        interaction_id="11223344",
                    )
                    dispatcher.shutdown()
            stdout_event = json.loads(captured.getvalue().strip())
            with open(path) as f:
                file_event = json.loads(f.read().strip())
            self.assertEqual(stdout_event, file_event)

    def test_siem_events_not_in_stdout_by_default(self):
        """With default config, SIEM events must NOT appear on stdout."""
        captured = io.StringIO()
        with mock.patch("sys.stdout", captured):
            with mock.patch.dict(os.environ, {
                "SECURITY_EVENT_STDOUT": "false",
                "SECURITY_EVENT_FILE_ENABLED": "false",
                "SYSLOG_ENABLED": "false",
            }, clear=False):
                dispatcher.configure()
                dispatcher.emit_event(
                    kind="probe", source_ip="1.2.3.4", method="GET",
                    endpoint="/", status_code=200, user_agent="bot",
                    interaction_id="aabb",
                )
                dispatcher.shutdown()
        self.assertEqual(captured.getvalue(), "")

    def test_operational_logs_not_in_siem_file(self):
        """SIEM file must only contain SIEM events, not Python logging records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "events.json")
            with mock.patch.dict(os.environ, {
                "SECURITY_EVENT_FILE_ENABLED": "true",
                "SECURITY_EVENT_FILE_PATH": path,
                "SECURITY_EVENT_STDOUT": "false",
            }, clear=False):
                dispatcher.configure()
                dispatcher.emit_event(
                    kind="unknown_token", source_ip="9.9.9.9", method="POST",
                    endpoint="/api/auth", status_code=401, user_agent="sqlmap",
                    interaction_id="deadbeef",
                )
                dispatcher.shutdown()
            with open(path) as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
            self.assertEqual(len(lines), 1)
            ev = json.loads(lines[0])
            # Must have SIEM fields
            self.assertIn("event_type", ev)
            self.assertIn("ttp", ev)
            # Must NOT have operational log fields
            self.assertNotIn("level", ev)
            self.assertNotIn("logger", ev)
            self.assertNotIn("message", ev)

    def test_syslog_exports_only_siem_events(self):
        """Syslog must export SIEM events only, not operational log records."""
        sent_packets = []

        class FakeSocket:
            def __init__(self, *a, **k): pass
            def settimeout(self, t): pass
            def sendto(self, data, addr): sent_packets.append(data.decode("utf-8", errors="replace"))
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with mock.patch("socket.socket", FakeSocket):
            with mock.patch.dict(os.environ, {
                "SECURITY_EVENT_STDOUT": "false",
                "SECURITY_EVENT_FILE_ENABLED": "false",
                "SYSLOG_ENABLED": "true",
                "SYSLOG_HOST": "127.0.0.1",
                "SYSLOG_PORT": "9999",
            }, clear=False):
                dispatcher.configure()
                dispatcher.emit_event(
                    kind="recon_openapi", source_ip="5.5.5.5", method="GET",
                    endpoint="/openapi.json", status_code=200, user_agent="Scanner",
                    interaction_id="cafecafe",
                )
                dispatcher.shutdown()

        self.assertEqual(len(sent_packets), 1)
        msg = sent_packets[0]
        # JSON in the syslog message must have SIEM fields only
        json_start = msg.find("{")
        self.assertGreater(json_start, -1)
        ev = json.loads(msg[json_start:])
        self.assertIn("event_type", ev)
        self.assertNotIn("level", ev)
        self.assertNotIn("logger", ev)


class TestTrustedProxyDedup(unittest.TestCase):
    def test_resolve_client_ip_cached_per_request(self):
        """resolve_client_ip must return cached result without re-evaluating."""
        import warnings
        from unittest.mock import MagicMock, patch
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from app.trusted_proxy import resolve_client_ip, _reset_cache

        _reset_cache()

        # Build a fake request with untrusted remote addr carrying forwarded headers
        mock_request = MagicMock()
        mock_request.client.host = "83.32.20.158"  # untrusted
        mock_request.headers = {"x-forwarded-for": "10.0.0.1", "cf-connecting-ip": "10.0.0.2"}
        mock_state = MagicMock(spec=[])  # no attributes initially
        mock_request.state = mock_state

        warning_calls = []
        with patch("app.trusted_proxy._logger") as mock_logger:
            mock_logger.warning.side_effect = lambda *a, **k: warning_calls.append(a)
            # Call twice — should only warn once
            ip1 = resolve_client_ip(mock_request)
            ip2 = resolve_client_ip(mock_request)

        self.assertEqual(ip1, ip2)
        # Warning should fire at most once despite two calls
        self.assertLessEqual(len(warning_calls), 1)


if __name__ == "__main__":
    unittest.main()
