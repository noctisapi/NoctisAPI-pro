"""NOC-028: scripts/check_app_ready.py's --http-port addition.

The DB-migration-state check (status_checks.ensure_ready) was already
exercised by the pre-existing use of this script as a Docker healthcheck;
these tests cover only the new, optional HTTP check, mocked so nothing
here makes a real network call.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.check_app_ready as check_app_ready  # noqa: E402


class TestCheckHttp(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_200_response_does_not_raise(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        check_app_ready._check_http(8000)  # no raise

    @patch("urllib.request.urlopen")
    def test_non_200_response_raises(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        with self.assertRaises(RuntimeError):
            check_app_ready._check_http(8000)

    @patch("urllib.request.urlopen", side_effect=OSError("connection refused"))
    def test_connection_failure_raises_runtime_error(self, _mock):
        with self.assertRaises(RuntimeError):
            check_app_ready._check_http(8000)

    @patch("urllib.request.urlopen")
    def test_requests_the_given_port_on_localhost(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        check_app_ready._check_http(9001)
        requested_url = mock_urlopen.call_args[0][0]
        self.assertEqual(requested_url, "http://127.0.0.1:9001/health")


class TestMainIntegration(unittest.TestCase):
    @patch("scripts.check_app_ready.status_checks.ensure_ready")
    def test_no_http_port_skips_http_check_entirely(self, mock_ensure_ready):
        mock_ensure_ready.return_value = {"current_revision": "abc", "expected_revision": "abc"}
        with patch.object(sys, "argv", ["check_app_ready.py"]):
            with patch("scripts.check_app_ready._check_http") as mock_http:
                self.assertEqual(check_app_ready.main(), 0)
                mock_http.assert_not_called()

    @patch("scripts.check_app_ready.status_checks.ensure_ready")
    def test_db_failure_returns_1_without_attempting_http(self, mock_ensure_ready):
        mock_ensure_ready.side_effect = RuntimeError("pending migrations")
        with patch.object(sys, "argv", ["check_app_ready.py", "--http-port", "8000"]):
            with patch("scripts.check_app_ready._check_http") as mock_http:
                self.assertEqual(check_app_ready.main(), 1)
                mock_http.assert_not_called()

    @patch("scripts.check_app_ready.status_checks.ensure_ready")
    @patch("scripts.check_app_ready._check_http")
    def test_http_failure_returns_1_even_if_db_is_fine(self, mock_http, mock_ensure_ready):
        mock_ensure_ready.return_value = {"current_revision": "abc", "expected_revision": "abc"}
        mock_http.side_effect = RuntimeError("GET failed")
        with patch.object(sys, "argv", ["check_app_ready.py", "--http-port", "8000"]):
            self.assertEqual(check_app_ready.main(), 1)

    @patch("scripts.check_app_ready.status_checks.ensure_ready")
    @patch("scripts.check_app_ready._check_http")
    def test_both_checks_passing_returns_0(self, mock_http, mock_ensure_ready):
        mock_ensure_ready.return_value = {"current_revision": "abc", "expected_revision": "abc"}
        with patch.object(sys, "argv", ["check_app_ready.py", "--http-port", "9001"]):
            self.assertEqual(check_app_ready.main(), 0)
            mock_http.assert_called_once_with(9001)


if __name__ == "__main__":
    unittest.main()
