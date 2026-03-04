"""Tests for app.reverse_proxy — reverse proxy compatibility.

Covers:
 - _parse_host_header: plain host, host+port, IPv6, bracketed IPv6+port
 - _build_base_url: scheme selection, default-port elision, explicit port
 - _rewrite_scope: scheme and server field rewriting from forwarded headers
 - get_public_base_url:
     * PUBLIC_BASE_URL env var (static override, highest priority)
     * trusted proxy + X-Forwarded-Proto/Host/Port headers
     * untrusted peer ignores forwarding headers (spoofing prevention)
     * no forwarding headers → raw socket fallback
 - ReverseProxyMiddleware:
     * rewrites scope for trusted proxy with forwarding headers
     * skips rewrite for untrusted peer
     * skips rewrite when PUBLIC_BASE_URL is set (static wins)
     * non-http/websocket scope types pass through unchanged
"""

from __future__ import annotations

import asyncio
import os
import unittest

from fastapi import Request

from app.trusted_proxy import _reset_cache as _reset_proxy_cache
from app.reverse_proxy import (
    _build_base_url,
    _parse_host_header,
    _rewrite_scope,
    get_public_base_url,
    ReverseProxyMiddleware,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _req(remote: str, **headers: str) -> Request:
    """Build a minimal Starlette Request with given remote IP and headers."""
    raw_headers = [
        (k.lower().replace("_", "-").encode(), v.encode())
        for k, v in headers.items()
    ]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": raw_headers,
        "client": (remote, 0),
        "server": ("app", 8000),
        "scheme": "http",
    }
    return Request(scope)


class _EnvOverride:
    """Context manager: temporarily set/unset env vars and reset caches."""

    _VARS = ("PUBLIC_BASE_URL", "TRUSTED_PROXIES")

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
        _reset_proxy_cache()
        # Force re-read of the module-level _PUBLIC_BASE_URL in reverse_proxy
        import app.reverse_proxy as rp
        rp._PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")
        return self

    def __exit__(self, *_):
        for k in self._VARS:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v
        _reset_proxy_cache()
        import app.reverse_proxy as rp
        rp._PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")


def _run(coro):
    """Run a coroutine synchronously."""
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# _parse_host_header
# ---------------------------------------------------------------------------


class TestParseHostHeader(unittest.TestCase):

    def test_plain_hostname(self):
        host, port = _parse_host_header("api.example.com")
        self.assertEqual(host, "api.example.com")
        self.assertIsNone(port)

    def test_hostname_with_port(self):
        host, port = _parse_host_header("api.example.com:9000")
        self.assertEqual(host, "api.example.com")
        self.assertEqual(port, 9000)

    def test_ipv4_with_port(self):
        host, port = _parse_host_header("10.0.0.1:8080")
        self.assertEqual(host, "10.0.0.1")
        self.assertEqual(port, 8080)

    def test_ipv4_without_port(self):
        host, port = _parse_host_header("10.0.0.1")
        self.assertEqual(host, "10.0.0.1")
        self.assertIsNone(port)

    def test_bracketed_ipv6_with_port(self):
        host, port = _parse_host_header("[::1]:8080")
        self.assertEqual(host, "[::1]")
        self.assertEqual(port, 8080)

    def test_bracketed_ipv6_without_port(self):
        host, port = _parse_host_header("[::1]")
        self.assertEqual(host, "[::1]")
        self.assertIsNone(port)

    def test_whitespace_stripped(self):
        host, port = _parse_host_header("  api.example.com  ")
        self.assertEqual(host, "api.example.com")
        self.assertIsNone(port)

    def test_port_80_parsed(self):
        host, port = _parse_host_header("example.com:80")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 80)


# ---------------------------------------------------------------------------
# _build_base_url
# ---------------------------------------------------------------------------


class TestBuildBaseUrl(unittest.TestCase):

    def test_https_default_port_omitted(self):
        url = _build_base_url("https", "api.example.com", "443")
        self.assertEqual(url, "https://api.example.com")

    def test_http_default_port_omitted(self):
        url = _build_base_url("http", "api.example.com", "80")
        self.assertEqual(url, "http://api.example.com")

    def test_non_default_port_included(self):
        url = _build_base_url("https", "api.example.com", "8443")
        self.assertEqual(url, "https://api.example.com:8443")

    def test_explicit_port_overrides_host_port(self):
        # X-Forwarded-Host includes port, X-Forwarded-Port overrides it
        url = _build_base_url("https", "api.example.com:9000", "8443")
        self.assertEqual(url, "https://api.example.com:8443")

    def test_port_in_host_header(self):
        url = _build_base_url("https", "api.example.com:8443", "")
        self.assertEqual(url, "https://api.example.com:8443")

    def test_unknown_proto_defaults_to_http(self):
        url = _build_base_url("ftp", "api.example.com", "")
        self.assertIn("http://", url)
        self.assertNotIn("ftp://", url)

    def test_empty_host_defaults_to_localhost(self):
        url = _build_base_url("https", "", "")
        self.assertIn("localhost", url)

    def test_no_trailing_slash(self):
        url = _build_base_url("https", "api.example.com", "")
        self.assertFalse(url.endswith("/"))


# ---------------------------------------------------------------------------
# _rewrite_scope
# ---------------------------------------------------------------------------


class TestRewriteScope(unittest.TestCase):

    def _base_scope(self) -> dict:
        return {
            "type": "http",
            "scheme": "http",
            "server": ("app", 8000),
            "headers": [],
        }

    def test_no_forwarded_headers_returns_same_scope(self):
        scope = self._base_scope()
        result = _rewrite_scope(scope, {})
        # Same object returned when there's nothing to rewrite
        self.assertIs(result, scope)

    def test_proto_header_rewrites_scheme(self):
        scope = self._base_scope()
        result = _rewrite_scope(scope, {"x-forwarded-proto": "https"})
        self.assertEqual(result["scheme"], "https")

    def test_host_header_rewrites_server(self):
        scope = self._base_scope()
        result = _rewrite_scope(scope, {"x-forwarded-proto": "https", "x-forwarded-host": "api.example.com"})
        bare_host, port = result["server"]
        self.assertEqual(bare_host, "api.example.com")
        self.assertEqual(port, 443)  # default for https

    def test_explicit_port_header(self):
        scope = self._base_scope()
        result = _rewrite_scope(scope, {
            "x-forwarded-proto": "https",
            "x-forwarded-host": "api.example.com",
            "x-forwarded-port": "8443",
        })
        _, port = result["server"]
        self.assertEqual(port, 8443)

    def test_ipv6_brackets_stripped_in_server(self):
        scope = self._base_scope()
        result = _rewrite_scope(scope, {
            "x-forwarded-proto": "http",
            "x-forwarded-host": "[::1]:8080",
        })
        bare_host, port = result["server"]
        self.assertEqual(bare_host, "::1")
        self.assertEqual(port, 8080)

    def test_original_scope_not_mutated(self):
        scope = self._base_scope()
        original_scheme = scope["scheme"]
        original_server = scope["server"]
        _rewrite_scope(scope, {"x-forwarded-proto": "https", "x-forwarded-host": "example.com"})
        self.assertEqual(scope["scheme"], original_scheme)
        self.assertEqual(scope["server"], original_server)

    def test_host_only_rewrites_server_not_scheme(self):
        scope = self._base_scope()
        result = _rewrite_scope(scope, {"x-forwarded-host": "api.example.com"})
        self.assertEqual(result["scheme"], "http")  # scheme unchanged
        bare_host, _ = result["server"]
        self.assertEqual(bare_host, "api.example.com")


# ---------------------------------------------------------------------------
# get_public_base_url
# ---------------------------------------------------------------------------


class TestGetPublicBaseUrl(unittest.TestCase):

    def test_static_env_var_takes_priority(self):
        """PUBLIC_BASE_URL env var overrides everything."""
        with _EnvOverride(PUBLIC_BASE_URL="https://static.example.com"):
            req = _req("1.2.3.4", x_forwarded_proto="http", x_forwarded_host="other.example.com")
            url = get_public_base_url(req)
        self.assertEqual(url, "https://static.example.com")

    def test_static_env_var_trailing_slash_stripped(self):
        with _EnvOverride(PUBLIC_BASE_URL="https://api.example.com/"):
            req = _req("127.0.0.1")
            url = get_public_base_url(req)
        self.assertEqual(url, "https://api.example.com")

    def test_trusted_proxy_xff_headers_used(self):
        """X-Forwarded-Proto/Host from a trusted proxy → derived URL."""
        with _EnvOverride(TRUSTED_PROXIES="10.0.0.0/8"):
            req = _req(
                "10.0.0.1",
                x_forwarded_proto="https",
                x_forwarded_host="api.example.com",
            )
            url = get_public_base_url(req)
        self.assertEqual(url, "https://api.example.com")

    def test_trusted_proxy_with_explicit_port(self):
        with _EnvOverride(TRUSTED_PROXIES="10.0.0.0/8"):
            req = _req(
                "10.0.0.1",
                x_forwarded_proto="https",
                x_forwarded_host="api.example.com",
                x_forwarded_port="8443",
            )
            url = get_public_base_url(req)
        self.assertEqual(url, "https://api.example.com:8443")

    def test_untrusted_peer_ignores_forwarded_headers(self):
        """Headers from an untrusted source must not influence the URL (anti-spoofing)."""
        with _EnvOverride(TRUSTED_PROXIES="192.168.0.0/24"):
            req = _req(
                "1.2.3.4",  # not in 192.168.0.0/24
                x_forwarded_proto="https",
                x_forwarded_host="evil.attacker.com",
            )
            url = get_public_base_url(req)
        # Must fall back to raw socket URL, not the attacker-controlled header
        self.assertNotIn("evil.attacker.com", url)

    def test_no_forwarded_headers_uses_raw_socket(self):
        """No headers and no env var → raw request.base_url."""
        with _EnvOverride():
            req = _req("127.0.0.1")
            url = get_public_base_url(req)
        # Should be based on the scope's server/scheme
        self.assertTrue(url.startswith("http"))
        self.assertFalse(url.endswith("/"))

    def test_default_trusted_networks_include_loopback(self):
        """When TRUSTED_PROXIES is unset, loopback peers are trusted by default."""
        with _EnvOverride():
            req = _req(
                "127.0.0.1",
                x_forwarded_proto="https",
                x_forwarded_host="api.example.com",
            )
            url = get_public_base_url(req)
        # 127.0.0.1 is in the default trusted list
        self.assertEqual(url, "https://api.example.com")

    def test_default_trusted_networks_include_private(self):
        """When TRUSTED_PROXIES is unset, RFC-1918 peers are trusted."""
        with _EnvOverride():
            req = _req(
                "172.16.0.1",
                x_forwarded_proto="https",
                x_forwarded_host="api.example.com",
            )
            url = get_public_base_url(req)
        self.assertEqual(url, "https://api.example.com")

    def test_no_forwarded_headers_even_from_trusted_proxy(self):
        """Trusted proxy with no forwarded headers → raw socket fallback."""
        with _EnvOverride(TRUSTED_PROXIES="10.0.0.0/8"):
            req = _req("10.0.0.1")  # no forwarded headers
            url = get_public_base_url(req)
        self.assertFalse(url.endswith("/"))
        # Should reflect raw scope (http://app:8000)
        self.assertIn("http://", url)


# ---------------------------------------------------------------------------
# ReverseProxyMiddleware (ASGI)
# ---------------------------------------------------------------------------


class TestReverseProxyMiddleware(unittest.TestCase):

    def _run_middleware(self, scope: dict, override: _EnvOverride | None = None) -> dict:
        """Run ReverseProxyMiddleware; return the scope received by the inner app."""
        received_scope = {}

        async def _inner(sc, receive, send):
            received_scope.update(sc)

        async def _go():
            mw = ReverseProxyMiddleware(_inner)
            await mw(scope, None, None)

        ctx = override or _EnvOverride()
        with ctx:
            _run(_go())
        return received_scope

    def _make_scope(self, remote: str, **header_pairs) -> dict:
        headers = [
            (k.lower().replace("_", "-").encode(), v.encode())
            for k, v in header_pairs.items()
        ]
        return {
            "type": "http",
            "scheme": "http",
            "server": ("app", 8000),
            "headers": headers,
            "client": (remote, 0),
        }

    def test_trusted_proxy_rewrites_scheme(self):
        scope = self._make_scope("10.0.0.1", x_forwarded_proto="https", x_forwarded_host="api.example.com")
        result = self._run_middleware(scope)
        self.assertEqual(result["scheme"], "https")

    def test_trusted_proxy_rewrites_server(self):
        scope = self._make_scope("10.0.0.1", x_forwarded_proto="https", x_forwarded_host="api.example.com")
        result = self._run_middleware(scope)
        self.assertEqual(result["server"][0], "api.example.com")
        self.assertEqual(result["server"][1], 443)

    def test_untrusted_peer_does_not_rewrite(self):
        scope = self._make_scope("1.2.3.4", x_forwarded_proto="https", x_forwarded_host="evil.attacker.com")
        override = _EnvOverride(TRUSTED_PROXIES="192.168.0.0/24")
        result = self._run_middleware(scope, override)
        # Scheme and server should be the originals
        self.assertEqual(result["scheme"], "http")
        self.assertEqual(result["server"], ("app", 8000))

    def test_static_public_url_skips_scope_rewrite(self):
        """When PUBLIC_BASE_URL is set, the middleware must not touch the scope."""
        scope = self._make_scope("10.0.0.1", x_forwarded_proto="https", x_forwarded_host="api.example.com")
        override = _EnvOverride(PUBLIC_BASE_URL="https://static.example.com")
        result = self._run_middleware(scope, override)
        # Scope should be unchanged — static URL takes priority
        self.assertEqual(result["scheme"], "http")
        self.assertEqual(result["server"], ("app", 8000))

    def test_non_http_scope_passes_through_unchanged(self):
        scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
        received = {}

        async def _inner(sc, receive, send):
            received.update(sc)

        async def _go():
            mw = ReverseProxyMiddleware(_inner)
            await mw(scope, None, None)

        with _EnvOverride():
            _run(_go())
        self.assertEqual(received["type"], "lifespan")

    def test_no_forwarded_headers_scope_unchanged(self):
        """Trusted proxy but no forwarding headers → scope unchanged."""
        scope = self._make_scope("10.0.0.1")  # no forwarded headers
        result = self._run_middleware(scope)
        self.assertEqual(result["scheme"], "http")
        self.assertEqual(result["server"], ("app", 8000))

    def test_original_scope_not_mutated_by_middleware(self):
        scope = self._make_scope("10.0.0.1", x_forwarded_proto="https", x_forwarded_host="api.example.com")
        original_scheme = scope["scheme"]
        original_server = scope["server"]
        self._run_middleware(scope)
        self.assertEqual(scope["scheme"], original_scheme)
        self.assertEqual(scope["server"], original_server)

    def test_explicit_port_propagated(self):
        scope = self._make_scope(
            "10.0.0.1",
            x_forwarded_proto="https",
            x_forwarded_host="api.example.com",
            x_forwarded_port="8443",
        )
        result = self._run_middleware(scope)
        self.assertEqual(result["server"][1], 8443)

    def test_http_port_80_elided_in_server_default(self):
        scope = self._make_scope("10.0.0.1", x_forwarded_proto="http", x_forwarded_host="api.example.com")
        result = self._run_middleware(scope)
        self.assertEqual(result["server"][1], 80)

    def test_websocket_scope_also_rewritten(self):
        scope = {
            "type": "websocket",
            "scheme": "ws",
            "server": ("app", 8000),
            "headers": [
                (b"x-forwarded-proto", b"wss"),
                (b"x-forwarded-host", b"ws.example.com"),
            ],
            "client": ("10.0.0.1", 0),
        }
        result = self._run_middleware(scope)
        # wss is not http/https but the host should still rewrite
        self.assertEqual(result["server"][0], "ws.example.com")


if __name__ == "__main__":
    unittest.main()
