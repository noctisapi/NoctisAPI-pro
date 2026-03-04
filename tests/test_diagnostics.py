"""Tests for app.diagnostics — startup environment diagnostics.

Covers:
 - DiagnosticResult:
     * __str__ formats [OK]/[WARN]/[ERROR] correctly
 - check_dns_resolution():
     * uses first EGRESS_REQUIRED_HOSTS hostname when set
     * falls back to gethostname() when EGRESS_REQUIRED_HOSTS is empty
     * [ok] on successful resolution
     * [error] on OSError
 - check_outbound_https():
     * [warn] when no :443 host in EGRESS_REQUIRED_HOSTS
     * [ok] when httpx head succeeds (any HTTP status)
     * [error] on httpx.ConnectError
     * [error] on httpx.TimeoutException
     * [error] when get_ssl_context() raises
 - check_proxy_configuration():
     * [warn] when no proxy env vars set
     * [ok] when HTTPS_PROXY set and TCP probe succeeds
     * [ok] when HTTP_PROXY (lowercase) set and TCP probe succeeds
     * [error] when proxy configured but TCP probe fails
 - check_tls_trust_store():
     * [ok] with detail "system CA only" when no custom certs
     * [ok] with detail "custom CA loaded" when SSL_CERT_FILE set (to valid file)
     * [error] when SSL_CERT_FILE points to a non-existent file
 - run_diagnostics():
     * returns exactly 4 results
     * never raises even when a check raises internally
     * passes timeout from EGRESS_CONNECT_TIMEOUT env var
     * all 4 labels present in results
"""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import httpx

from app.diagnostics import (
    DiagnosticResult,
    check_dns_resolution,
    check_outbound_https,
    check_proxy_configuration,
    check_tls_trust_store,
    run_diagnostics,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _EnvOverride:
    _VARS = (
        "EGRESS_REQUIRED_HOSTS",
        "EGRESS_CONNECT_TIMEOUT",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "HP_EXTRA_CERTS_DIR",
    )

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


_ADDR_INFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 80))]


# ---------------------------------------------------------------------------
# DiagnosticResult
# ---------------------------------------------------------------------------


class TestDiagnosticResult(unittest.TestCase):

    def test_str_ok(self):
        r = DiagnosticResult("DNS resolution", "ok", "resolved 'example.com'")
        self.assertIn("[OK]", str(r))
        self.assertIn("DNS resolution", str(r))
        self.assertIn("resolved 'example.com'", str(r))

    def test_str_warn(self):
        r = DiagnosticResult("proxy", "warn", "not configured")
        self.assertIn("[WARN]", str(r))

    def test_str_error(self):
        r = DiagnosticResult("TLS trust store", "error", "file not found")
        self.assertIn("[ERROR]", str(r))

    def test_str_no_detail(self):
        r = DiagnosticResult("DNS resolution", "ok")
        s = str(r)
        self.assertIn("[OK]", s)
        self.assertNotIn("—", s)


# ---------------------------------------------------------------------------
# check_dns_resolution
# ---------------------------------------------------------------------------


class TestCheckDnsResolution(unittest.TestCase):

    def test_ok_with_egress_host(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com"), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO):
            result = check_dns_resolution()
        self.assertEqual(result.status, "ok")
        self.assertIn("example.com", result.detail)

    def test_ok_with_hostname_fallback(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS=""), \
             patch("socket.gethostname", return_value="myhost"), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO):
            result = check_dns_resolution()
        self.assertEqual(result.status, "ok")
        self.assertIn("myhost", result.detail)

    def test_loopback_hosts_skipped(self):
        """Loopback entries in EGRESS_REQUIRED_HOSTS should not be used as DNS target."""
        with _EnvOverride(EGRESS_REQUIRED_HOSTS="localhost"), \
             patch("socket.gethostname", return_value="myhost"), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO):
            result = check_dns_resolution()
        self.assertEqual(result.status, "ok")
        # Should fall back to hostname, not use "localhost" as external target
        self.assertIn("myhost", result.detail)

    def test_error_on_oserror(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS="bad.invalid"), \
             patch("socket.getaddrinfo", side_effect=OSError("NXDOMAIN")):
            result = check_dns_resolution()
        self.assertEqual(result.status, "error")
        self.assertIn("NXDOMAIN", result.detail)

    def test_label_is_dns_resolution(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS=""), \
             patch("socket.gethostname", return_value="host"), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO):
            result = check_dns_resolution()
        self.assertEqual(result.label, "DNS resolution")


# ---------------------------------------------------------------------------
# check_outbound_https
# ---------------------------------------------------------------------------


class TestCheckOutboundHttps(unittest.TestCase):

    def test_warn_when_no_443_target(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com"):
            # no :443, only bare hostname
            result = check_outbound_https()
        self.assertEqual(result.status, "warn")
        self.assertIn("no :443 target", result.detail)

    def test_warn_when_egress_empty(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS=""):
            result = check_outbound_https()
        self.assertEqual(result.status, "warn")

    def test_ok_on_successful_head(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = MagicMock()
        mock_client.__enter__ = lambda s: s
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head.return_value = mock_resp

        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com:443"), \
             patch("app.tls_config.get_ssl_context", return_value=MagicMock()), \
             patch("app.proxy_config.build_httpx_mounts", return_value={}), \
             patch("httpx.Client", return_value=mock_client):
            result = check_outbound_https()

        self.assertEqual(result.status, "ok")
        self.assertIn("200", result.detail)

    def test_ok_on_any_http_status(self):
        """Even a 404 or 502 means HTTPS connectivity works."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = MagicMock()
        mock_client.__enter__ = lambda s: s
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head.return_value = mock_resp

        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com:443"), \
             patch("app.tls_config.get_ssl_context", return_value=MagicMock()), \
             patch("app.proxy_config.build_httpx_mounts", return_value={}), \
             patch("httpx.Client", return_value=mock_client):
            result = check_outbound_https()

        self.assertEqual(result.status, "ok")

    def test_error_on_connect_error(self):
        mock_client = MagicMock()
        mock_client.__enter__ = lambda s: s
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head.side_effect = httpx.ConnectError("connection refused")

        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com:443"), \
             patch("app.tls_config.get_ssl_context", return_value=MagicMock()), \
             patch("app.proxy_config.build_httpx_mounts", return_value={}), \
             patch("httpx.Client", return_value=mock_client):
            result = check_outbound_https()

        self.assertEqual(result.status, "error")

    def test_error_on_timeout(self):
        mock_client = MagicMock()
        mock_client.__enter__ = lambda s: s
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.head.side_effect = httpx.TimeoutException("timed out")

        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com:443"), \
             patch("app.tls_config.get_ssl_context", return_value=MagicMock()), \
             patch("app.proxy_config.build_httpx_mounts", return_value={}), \
             patch("httpx.Client", return_value=mock_client):
            result = check_outbound_https()

        self.assertEqual(result.status, "error")
        self.assertIn("timed out", result.detail)

    def test_error_when_ssl_context_unavailable(self):
        with _EnvOverride(EGRESS_REQUIRED_HOSTS="example.com:443"), \
             patch("app.tls_config.get_ssl_context", side_effect=ssl.SSLError("bad cert")):
            result = check_outbound_https()

        self.assertEqual(result.status, "error")
        self.assertIn("TLS context unavailable", result.detail)


# ---------------------------------------------------------------------------
# check_proxy_configuration
# ---------------------------------------------------------------------------


class TestCheckProxyConfiguration(unittest.TestCase):

    def test_warn_when_no_proxy_set(self):
        with _EnvOverride():
            result = check_proxy_configuration()
        self.assertEqual(result.status, "warn")
        self.assertIn("not configured", result.detail)

    def test_ok_when_https_proxy_reachable(self):
        mock_conn = MagicMock()
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__ = MagicMock(return_value=False)

        with _EnvOverride(HTTPS_PROXY="http://proxy.example.com:3128"), \
             patch("socket.create_connection", return_value=mock_conn):
            result = check_proxy_configuration()

        self.assertEqual(result.status, "ok")
        self.assertIn("proxy.example.com", result.detail)

    def test_ok_when_http_proxy_lowercase_reachable(self):
        mock_conn = MagicMock()
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__ = MagicMock(return_value=False)

        with _EnvOverride(http_proxy="http://proxy.internal:8080"), \
             patch("socket.create_connection", return_value=mock_conn):
            result = check_proxy_configuration()

        self.assertEqual(result.status, "ok")

    def test_error_when_proxy_unreachable(self):
        with _EnvOverride(HTTPS_PROXY="http://proxy.example.com:3128"), \
             patch("socket.create_connection", side_effect=OSError("Connection refused")):
            result = check_proxy_configuration()

        self.assertEqual(result.status, "error")
        self.assertIn("unreachable", result.detail)
        self.assertIn("proxy.example.com", result.detail)

    def test_label_is_proxy(self):
        with _EnvOverride():
            result = check_proxy_configuration()
        self.assertEqual(result.label, "proxy")


# ---------------------------------------------------------------------------
# check_tls_trust_store
# ---------------------------------------------------------------------------


class TestCheckTlsTrustStore(unittest.TestCase):

    def test_ok_system_ca_only(self):
        with _EnvOverride():
            result = check_tls_trust_store()
        self.assertEqual(result.status, "ok")
        self.assertIn("system CA only", result.detail)

    def test_ok_with_custom_cert_file(self):
        # Write a trivial PEM file — we mock build_ssl_context so it won't actually parse it
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            cert_path = f.name
        try:
            with _EnvOverride(SSL_CERT_FILE=cert_path), \
                 patch("app.tls_config.build_ssl_context"):
                result = check_tls_trust_store()
            self.assertEqual(result.status, "ok")
            self.assertIn("custom CA loaded", result.detail)
        finally:
            os.unlink(cert_path)

    def test_error_when_build_raises_file_not_found(self):
        with _EnvOverride(SSL_CERT_FILE="/nonexistent/ca.pem"), \
             patch(
                "app.tls_config.build_ssl_context",
                side_effect=FileNotFoundError("CA bundle not found"),
            ):
            result = check_tls_trust_store()
        self.assertEqual(result.status, "error")
        self.assertIn("CA bundle not found", result.detail)

    def test_error_when_build_raises_ssl_error(self):
        with _EnvOverride(), \
             patch(
                "app.tls_config.build_ssl_context",
                side_effect=ssl.SSLError("bad cert"),
             ):
            result = check_tls_trust_store()
        self.assertEqual(result.status, "error")

    def test_label_is_tls_trust_store(self):
        with _EnvOverride():
            result = check_tls_trust_store()
        self.assertEqual(result.label, "TLS trust store")


# ---------------------------------------------------------------------------
# run_diagnostics
# ---------------------------------------------------------------------------


class TestRunDiagnostics(unittest.TestCase):

    def _mock_all(self, *, egress="", proxy=""):
        """Context managers that make all four checks pass trivially."""
        ctx = _EnvOverride(EGRESS_REQUIRED_HOSTS=egress)
        getaddrinfo = patch("socket.getaddrinfo", return_value=_ADDR_INFO)
        gethostname = patch("socket.gethostname", return_value="testhost")
        build_ssl = patch("app.tls_config.build_ssl_context")
        return ctx, getaddrinfo, gethostname, build_ssl

    def test_returns_four_results(self):
        with _EnvOverride(), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.gethostname", return_value="testhost"), \
             patch("app.tls_config.build_ssl_context"):
            results = run_diagnostics()
        self.assertEqual(len(results), 4)

    def test_all_labels_present(self):
        with _EnvOverride(), \
             patch("socket.getaddrinfo", return_value=_ADDR_INFO), \
             patch("socket.gethostname", return_value="testhost"), \
             patch("app.tls_config.build_ssl_context"):
            results = run_diagnostics()
        labels = {r.label for r in results}
        self.assertIn("DNS resolution", labels)
        self.assertIn("outbound HTTPS", labels)
        self.assertIn("proxy", labels)
        self.assertIn("TLS trust store", labels)

    def test_never_raises_when_check_raises(self):
        with _EnvOverride(), \
             patch("app.diagnostics.check_dns_resolution", side_effect=RuntimeError("boom")), \
             patch("app.diagnostics.check_outbound_https", return_value=DiagnosticResult("outbound HTTPS", "warn")), \
             patch("app.diagnostics.check_proxy_configuration", return_value=DiagnosticResult("proxy", "warn")), \
             patch("app.diagnostics.check_tls_trust_store", return_value=DiagnosticResult("TLS trust store", "ok")):
            try:
                results = run_diagnostics()
            except Exception as exc:
                self.fail(f"run_diagnostics raised unexpectedly: {exc!r}")
        # The crashed check should produce an error result, not crash the runner
        self.assertEqual(len(results), 4)
        crashed = next(r for r in results if r.status == "error")
        self.assertIn("unexpectedly", crashed.detail)

    def test_timeout_from_env_var(self):
        """EGRESS_CONNECT_TIMEOUT is passed as timeout to each check."""
        seen_timeouts = []

        def _fake_dns(*, timeout=5.0):
            seen_timeouts.append(("dns", timeout))
            return DiagnosticResult("DNS resolution", "ok")

        def _fake_https(*, timeout=5.0):
            seen_timeouts.append(("https", timeout))
            return DiagnosticResult("outbound HTTPS", "warn")

        def _fake_proxy(*, timeout=5.0):
            seen_timeouts.append(("proxy", timeout))
            return DiagnosticResult("proxy", "warn")

        with _EnvOverride(EGRESS_CONNECT_TIMEOUT="3"), \
             patch("app.diagnostics.check_dns_resolution", side_effect=_fake_dns), \
             patch("app.diagnostics.check_outbound_https", side_effect=_fake_https), \
             patch("app.diagnostics.check_proxy_configuration", side_effect=_fake_proxy), \
             patch("app.diagnostics.check_tls_trust_store",
                   return_value=DiagnosticResult("TLS trust store", "ok")):
            run_diagnostics()

        self.assertEqual(seen_timeouts, [("dns", 3.0), ("https", 3.0), ("proxy", 3.0)])

    def test_invalid_timeout_env_uses_default(self):
        """Invalid EGRESS_CONNECT_TIMEOUT falls back to 5.0 silently."""
        seen_timeouts = []

        def _fake_dns(*, timeout=5.0):
            seen_timeouts.append(timeout)
            return DiagnosticResult("DNS resolution", "ok")

        with _EnvOverride(EGRESS_CONNECT_TIMEOUT="notanumber"), \
             patch("app.diagnostics.check_dns_resolution", side_effect=_fake_dns), \
             patch("app.diagnostics.check_outbound_https",
                   return_value=DiagnosticResult("outbound HTTPS", "warn")), \
             patch("app.diagnostics.check_proxy_configuration",
                   return_value=DiagnosticResult("proxy", "warn")), \
             patch("app.diagnostics.check_tls_trust_store",
                   return_value=DiagnosticResult("TLS trust store", "ok")):
            run_diagnostics()

        self.assertEqual(seen_timeouts, [5.0])


if __name__ == "__main__":
    unittest.main()
