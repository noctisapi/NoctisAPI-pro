"""NOC-024: scripts/verify_domain.py -- DNS/TLS post-deploy verification.

All network calls are mocked; this never makes a real DNS/TLS call, so it
can't be flaky in CI regardless of network conditions there.
"""
from __future__ import annotations

import datetime
import socket
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.verify_domain as verify_domain  # noqa: E402


def _future_cert_not_after(days: int) -> str:
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    return when.strftime("%b %d %H:%M:%S %Y GMT")


class TestResolveHost(unittest.TestCase):
    @patch("socket.getaddrinfo")
    def test_resolves_to_sorted_unique_addresses(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, None, None, "", ("203.0.113.10", 0)),
            (socket.AF_INET, None, None, "", ("203.0.113.10", 0)),  # duplicate
            (socket.AF_INET6, None, None, "", ("2001:db8::1", 0, 0, 0)),
        ]
        addrs = verify_domain.resolve_host("example.com")
        self.assertEqual(addrs, sorted({"203.0.113.10", "2001:db8::1"}))

    @patch("socket.getaddrinfo", side_effect=socket.gaierror("nope"))
    def test_nonresolving_domain_raises_check_failed(self, _mock):
        with self.assertRaises(verify_domain.CheckFailed):
            verify_domain.resolve_host("does-not-exist.invalid")


class TestCheckExpectedIp(unittest.TestCase):
    def test_matching_ip_passes_silently(self):
        verify_domain.check_expected_ip(["203.0.113.10", "203.0.113.11"], "203.0.113.10")  # no raise

    def test_mismatched_ip_raises(self):
        with self.assertRaises(verify_domain.CheckFailed):
            verify_domain.check_expected_ip(["203.0.113.11"], "203.0.113.10")


class TestCheckTls(unittest.TestCase):
    def _mock_tls_connection(self, mock_create_connection, mock_context_cls, *, not_after: str):
        mock_tls_sock = MagicMock()
        mock_tls_sock.getpeercert.return_value = {"notAfter": not_after}
        mock_tls_sock.__enter__.return_value = mock_tls_sock
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_tls_sock
        mock_context_cls.return_value = mock_context
        mock_create_connection.return_value.__enter__.return_value = MagicMock()

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_valid_cert_with_plenty_of_time_left_passes(self, mock_create_connection, mock_context_cls):
        self._mock_tls_connection(
            mock_create_connection, mock_context_cls, not_after=_future_cert_not_after(90)
        )
        message = verify_domain.check_tls("example.com", warn_days=14)
        self.assertIn("valid", message)

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_cert_expiring_soon_raises(self, mock_create_connection, mock_context_cls):
        self._mock_tls_connection(
            mock_create_connection, mock_context_cls, not_after=_future_cert_not_after(5)
        )
        with self.assertRaises(verify_domain.CheckFailed):
            verify_domain.check_tls("example.com", warn_days=14)

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_already_expired_cert_raises(self, mock_create_connection, mock_context_cls):
        self._mock_tls_connection(
            mock_create_connection, mock_context_cls, not_after=_future_cert_not_after(-1)
        )
        with self.assertRaises(verify_domain.CheckFailed):
            verify_domain.check_tls("example.com", warn_days=14)

    @patch("socket.create_connection", side_effect=OSError("connection refused"))
    def test_connection_failure_raises_check_failed_not_oserror(self, _mock):
        with self.assertRaises(verify_domain.CheckFailed):
            verify_domain.check_tls("example.com")

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_cert_verification_failure_raises_check_failed(self, mock_create_connection, mock_context_cls):
        mock_context = MagicMock()
        mock_context.wrap_socket.side_effect = ssl.SSLCertVerificationError("hostname mismatch")
        mock_context_cls.return_value = mock_context
        mock_create_connection.return_value.__enter__.return_value = MagicMock()
        with self.assertRaises(verify_domain.CheckFailed):
            verify_domain.check_tls("example.com")


class TestMainIntegration(unittest.TestCase):
    """Drives the real main() entrypoint and argument parsing, with the
    network-touching functions mocked -- proves the CLI wiring itself
    (exit codes, --skip-tls, --no-ip-check) without touching the network."""

    @patch("scripts.verify_domain.check_tls", return_value="TLS: ok")
    @patch("scripts.verify_domain.resolve_host", return_value=["203.0.113.10"])
    def test_everything_passing_exits_zero(self, _mock_resolve, _mock_tls):
        with patch.object(sys, "argv", ["verify_domain.py", "--host", "example.com"]):
            self.assertEqual(verify_domain.main(), 0)

    @patch("scripts.verify_domain.resolve_host", side_effect=verify_domain.CheckFailed("DNS: nope"))
    def test_dns_failure_exits_nonzero_and_skips_tls(self, _mock_resolve):
        with patch.object(sys, "argv", ["verify_domain.py", "--host", "example.com"]):
            with patch("scripts.verify_domain.check_tls") as mock_tls:
                self.assertEqual(verify_domain.main(), 1)
                mock_tls.assert_not_called()

    @patch("scripts.verify_domain.resolve_host", return_value=["203.0.113.10"])
    def test_skip_tls_flag_skips_the_tls_check(self, _mock_resolve):
        with patch.object(sys, "argv", ["verify_domain.py", "--host", "example.com", "--skip-tls"]):
            with patch("scripts.verify_domain.check_tls") as mock_tls:
                self.assertEqual(verify_domain.main(), 0)
                mock_tls.assert_not_called()

    def test_no_host_given_and_no_env_var_exits_with_usage_error(self):
        with patch.object(sys, "argv", ["verify_domain.py"]):
            with patch.dict("os.environ", {"HP_PUBLIC_HOST": ""}):
                self.assertEqual(verify_domain.main(), 2)

    @patch("scripts.verify_domain.check_tls", return_value="TLS: ok")
    @patch("scripts.verify_domain.resolve_host", return_value=["203.0.113.10"])
    def test_wrong_expected_ip_exits_nonzero(self, _mock_resolve, _mock_tls):
        with patch.object(
            sys, "argv", ["verify_domain.py", "--host", "example.com", "--expected-ip", "198.51.100.1"]
        ):
            self.assertEqual(verify_domain.main(), 1)

    @patch("scripts.verify_domain.check_tls", return_value="TLS: ok")
    @patch("scripts.verify_domain.resolve_host", return_value=["203.0.113.10"])
    def test_no_ip_check_flag_ignores_mismatched_expected_ip(self, _mock_resolve, _mock_tls):
        with patch.object(
            sys,
            "argv",
            ["verify_domain.py", "--host", "example.com", "--expected-ip", "198.51.100.1", "--no-ip-check"],
        ):
            self.assertEqual(verify_domain.main(), 0)


if __name__ == "__main__":
    unittest.main()
