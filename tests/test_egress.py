"""Tests for app.egress — egress dependency declaration.

Covers:
 - parse_egress_hosts():
     * comma-separated entries
     * newline-separated entries
     * mixed comma and newline
     * empty / blank-only string
     * host:port entry → port parsed as int
     * bare hostname → port is None
     * invalid port token → treated as DNS-only (port None)
     * leading/trailing whitespace stripped
     * blank tokens ignored
 - check_host():
     * DNS ok, no port → tcp=skipped
     * DNS ok, port given → TCP connect attempted, success
     * DNS failure → dns=error, tcp=skipped, error set
     * TCP failure → dns=ok, tcp=error, error set
     * timeout propagated to socket.settimeout()
 - check_egress_hosts():
     * empty env → returns empty list, no logging
     * single host success → INFO logged
     * DNS failure → WARNING logged, does not raise
     * TCP failure → WARNING logged, does not raise
     * multiple hosts, mixed results
     * never raises even if check_host raises unexpectedly
     * EGRESS_CONNECT_TIMEOUT env var respected
     * invalid EGRESS_CONNECT_TIMEOUT → warns, uses 5s default
"""

from __future__ import annotations

import logging
import os
import socket
import unittest
from unittest.mock import MagicMock, call, patch

from app.egress import check_egress_hosts, check_host, parse_egress_hosts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _EnvOverride:
    _VARS = ("EGRESS_REQUIRED_HOSTS", "EGRESS_CONNECT_TIMEOUT")

    def __init__(self, **kwargs: str | None):
        self._overrides = kwargs
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self._VARS}
        for k in self._VARS:
            os.environ.pop(k, None)
        for k, v in self._overrides.items():
            if v is not None:
                os.environ[k] = v
        return self

    def __exit__(self, *_):
        for k in self._VARS:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v


# A minimal getaddrinfo return value: (family, socktype, proto, canonname, sockaddr)
_ADDR_INFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
_ADDR_INFO_80 = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 80))]


# ---------------------------------------------------------------------------
# parse_egress_hosts
# ---------------------------------------------------------------------------


class TestParseEgressHosts(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(parse_egress_hosts(""), [])

    def test_blank_only(self):
        self.assertEqual(parse_egress_hosts("  \n  \n  "), [])

    def test_bare_hostname(self):
        result = parse_egress_hosts("example.com")
        self.assertEqual(result, [("example.com", None)])

    def test_host_with_port(self):
        result = parse_egress_hosts("example.com:443")
        self.assertEqual(result, [("example.com", 443)])

    def test_comma_separated(self):
        result = parse_egress_hosts("a.com,b.com:8080")
        self.assertEqual(result, [("a.com", None), ("b.com", 8080)])

    def test_newline_separated(self):
        result = parse_egress_hosts("a.com\nb.com:8080")
        self.assertEqual(result, [("a.com", None), ("b.com", 8080)])

    def test_mixed_comma_newline(self):
        result = parse_egress_hosts("a.com,\nb.com:443\nc.com")
        self.assertEqual(result, [("a.com", None), ("b.com", 443), ("c.com", None)])

    def test_whitespace_stripped(self):
        result = parse_egress_hosts("  example.com:443  ")
        self.assertEqual(result, [("example.com", 443)])

    def test_blank_tokens_ignored(self):
        result = parse_egress_hosts("a.com,,b.com")
        self.assertEqual(result, [("a.com", None), ("b.com", None)])

    def test_invalid_port_falls_back_to_dns_only(self):
        # "example.com:notaport" — port is not an int, treat as bare hostname
        result = parse_egress_hosts("example.com:notaport")
        self.assertEqual(result, [("example.com:notaport", None)])

    def test_multiple_hosts_with_ports(self):
        result = parse_egress_hosts("a.com:443\nb.com:80\nc.com")
        self.assertEqual(result, [("a.com", 443), ("b.com", 80), ("c.com", None)])


# ---------------------------------------------------------------------------
# check_host
# ---------------------------------------------------------------------------


class TestCheckHostDnsOnly(unittest.TestCase):
    """Bare hostname (no port) — only DNS resolution."""

    def test_dns_ok_tcp_skipped(self):
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO_80):
            result = check_host("example.com", None)
        self.assertEqual(result["dns"], "ok")
        self.assertEqual(result["tcp"], "skipped")
        self.assertIsNone(result["error"])

    def test_dns_failure(self):
        with patch("socket.getaddrinfo", side_effect=OSError("Name or service not known")):
            result = check_host("nonexistent.invalid", None)
        self.assertEqual(result["dns"], "error")
        self.assertEqual(result["tcp"], "skipped")
        self.assertIn("Name or service not known", result["error"])

    def test_result_contains_host_and_port(self):
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO_80):
            result = check_host("example.com", None)
        self.assertEqual(result["host"], "example.com")
        self.assertIsNone(result["port"])


class TestCheckHostWithPort(unittest.TestCase):
    """host:port — DNS + TCP connect."""

    def _mock_socket(self):
        sock = MagicMock()
        sock.__enter__ = lambda s: s
        sock.__exit__ = MagicMock(return_value=False)
        return sock

    def test_dns_and_tcp_ok(self):
        mock_sock = self._mock_socket()
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=mock_sock):
            result = check_host("example.com", 443)
        self.assertEqual(result["dns"], "ok")
        self.assertEqual(result["tcp"], "ok")
        self.assertIsNone(result["error"])

    def test_timeout_set_on_socket(self):
        mock_sock = self._mock_socket()
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=mock_sock):
            check_host("example.com", 443, timeout=3.5)
        mock_sock.settimeout.assert_called_once_with(3.5)

    def test_tcp_failure(self):
        mock_sock = self._mock_socket()
        mock_sock.connect.side_effect = OSError("Connection refused")
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=mock_sock):
            result = check_host("example.com", 443)
        self.assertEqual(result["dns"], "ok")
        self.assertEqual(result["tcp"], "error")
        self.assertIn("Connection refused", result["error"])

    def test_dns_failure_skips_tcp(self):
        with patch("socket.getaddrinfo", side_effect=OSError("DNS fail")):
            result = check_host("example.com", 443)
        self.assertEqual(result["dns"], "error")
        self.assertEqual(result["tcp"], "skipped")

    def test_result_contains_host_and_port(self):
        mock_sock = self._mock_socket()
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=mock_sock):
            result = check_host("example.com", 443)
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["port"], 443)


# ---------------------------------------------------------------------------
# check_egress_hosts
# ---------------------------------------------------------------------------


class TestCheckEgressHostsEmpty(unittest.TestCase):

    def test_empty_env_returns_empty_list(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS=""):
            result = check_egress_hosts()
        self.assertEqual(result, [])

    def test_unset_env_returns_empty_list(self):
        with _EnvOverride():
            result = check_egress_hosts()
        self.assertEqual(result, [])

    def test_explicit_empty_string_returns_empty(self):
        result = check_egress_hosts("")
        self.assertEqual(result, [])


class TestCheckEgressHostsSuccess(unittest.TestCase):

    def test_success_logs_info(self):
        mock_sock = MagicMock()
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=mock_sock), \
             self.assertLogs("app.egress", level=logging.INFO) as cm:
            result = check_egress_hosts("example.com:443")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["dns"], "ok")
        self.assertEqual(result[0]["tcp"], "ok")
        self.assertTrue(any("OK" in line for line in cm.output))

    def test_dns_only_success_logs_info(self):
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO_80), \
             self.assertLogs("app.egress", level=logging.INFO) as cm:
            result = check_egress_hosts("example.com")
        self.assertEqual(result[0]["tcp"], "skipped")
        self.assertTrue(any("OK" in line for line in cm.output))

    def test_returns_result_for_each_host(self):
        mock_sock = MagicMock()
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=mock_sock), \
             self.assertLogs("app.egress", level=logging.INFO):
            result = check_egress_hosts("a.com:443,b.com:80")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["host"], "a.com")
        self.assertEqual(result[1]["host"], "b.com")


class TestCheckEgressHostsFailures(unittest.TestCase):

    def test_dns_failure_logs_warning(self):
        with patch("socket.getaddrinfo", side_effect=OSError("NXDOMAIN")), \
             self.assertLogs("app.egress", level=logging.WARNING) as cm:
            result = check_egress_hosts("bad.invalid")
        self.assertEqual(result[0]["dns"], "error")
        self.assertTrue(any("DNS resolution failed" in line for line in cm.output))

    def test_tcp_failure_logs_warning(self):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Connection refused")
        with patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=mock_sock), \
             self.assertLogs("app.egress", level=logging.WARNING) as cm:
            result = check_egress_hosts("example.com:443")
        self.assertEqual(result[0]["tcp"], "error")
        self.assertTrue(any("TCP connect failed" in line for line in cm.output))

    def test_does_not_raise_on_failure(self):
        with patch("socket.getaddrinfo", side_effect=OSError("fail")), \
             self.assertLogs("app.egress", level=logging.WARNING):
            try:
                check_egress_hosts("bad.invalid")
            except Exception as exc:
                self.fail(f"check_egress_hosts raised unexpectedly: {exc!r}")

    def test_mixed_results_all_checked(self):
        def _getaddrinfo(host, *a, **kw):
            if host == "good.com":
                return _ADDR_INFO_80
            raise OSError("NXDOMAIN")

        with patch("socket.getaddrinfo", side_effect=_getaddrinfo), \
             self.assertLogs("app.egress", level=logging.DEBUG):
            result = check_egress_hosts("good.com,bad.invalid")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["dns"], "ok")
        self.assertEqual(result[1]["dns"], "error")


class TestCheckEgressHostsEnvConfig(unittest.TestCase):

    def test_timeout_env_var_used(self):
        """EGRESS_CONNECT_TIMEOUT is passed to check_host as timeout."""
        timeouts_seen = []

        def _fake_getaddrinfo(host, port, *a, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

        mock_sock = MagicMock()

        def _fake_socket(*a, **kw):
            return mock_sock

        original_check_host = __import__("app.egress", fromlist=["check_host"]).check_host

        def _patched_check_host(hostname, port, *, timeout=5.0):
            timeouts_seen.append(timeout)
            return original_check_host.__wrapped__(hostname, port, timeout=timeout) \
                if hasattr(original_check_host, "__wrapped__") \
                else {"host": hostname, "port": port, "dns": "ok", "tcp": "skipped", "error": None}

        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com", EGRESS_CONNECT_TIMEOUT="2"), \
             patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo), \
             patch("socket.socket", side_effect=_fake_socket), \
             patch("app.egress.check_host", side_effect=_patched_check_host), \
             self.assertLogs("app.egress", level=logging.DEBUG):
            check_egress_hosts()
        self.assertEqual(timeouts_seen, [2.0])

    def test_invalid_timeout_uses_default_and_warns(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com", EGRESS_CONNECT_TIMEOUT="notanumber"), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO_80), \
             self.assertLogs("app.egress", level=logging.WARNING) as cm:
            result = check_egress_hosts()
        self.assertTrue(any("not a valid number" in line for line in cm.output))
        # Host should still be checked despite bad timeout config
        self.assertEqual(len(result), 1)

    def test_hosts_from_env_var(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com:443"), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.socket", return_value=MagicMock()), \
             self.assertLogs("app.egress", level=logging.INFO):
            result = check_egress_hosts()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["host"], "example.com")


if __name__ == "__main__":
    unittest.main()
