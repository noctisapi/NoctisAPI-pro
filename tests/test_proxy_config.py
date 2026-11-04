"""Unit tests for app.proxy_config — corporate egress proxy support."""

from __future__ import annotations

import os
import unittest

import httpx

from app.proxy_config import build_httpx_mounts, _parse_no_proxy, _no_proxy_to_httpx_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _EnvOverride:
    """Context manager: apply env var overrides, restore originals on exit."""

    _PROXY_VARS = (
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "no_proxy",
    )

    def __init__(self, **kwargs: str | None):
        self._overrides = kwargs
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self._PROXY_VARS}
        for k in self._PROXY_VARS:
            os.environ.pop(k, None)
        for k, v in self._overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *_):
        for k in self._PROXY_VARS:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v


# ---------------------------------------------------------------------------
# build_httpx_mounts — no proxy configured
# ---------------------------------------------------------------------------


class TestBuildHttpxMountsNoProxy(unittest.TestCase):
    """When no proxy env vars are set the function must be a no-op."""

    def test_returns_empty_dict_when_no_proxy_vars(self):
        with _EnvOverride():
            result = build_httpx_mounts()
        self.assertEqual(result, {})

    def test_returns_empty_dict_when_vars_are_blank(self):
        with _EnvOverride(HTTP_PROXY="", HTTPS_PROXY="", NO_PROXY=""):
            result = build_httpx_mounts()
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# build_httpx_mounts — proxy configured
# ---------------------------------------------------------------------------


class TestBuildHttpxMountsWithProxy(unittest.TestCase):
    """When a proxy is configured, the map must route traffic through it."""

    PROXY = "http://proxy.company.local:3128"

    def _get(self, key: str, **env) -> object:
        with _EnvOverride(**env):
            return build_httpx_mounts().get(key)

    def test_http_catch_all_is_transport(self):
        val = self._get("http://", HTTP_PROXY=self.PROXY)
        self.assertIsInstance(val, httpx.HTTPTransport)

    def test_https_catch_all_is_transport(self):
        val = self._get("https://", HTTPS_PROXY=self.PROXY)
        self.assertIsInstance(val, httpx.HTTPTransport)

    def test_both_schemes_when_both_vars_set(self):
        with _EnvOverride(HTTP_PROXY=self.PROXY, HTTPS_PROXY=self.PROXY):
            mounts = build_httpx_mounts()
        self.assertIsInstance(mounts.get("http://"), httpx.HTTPTransport)
        self.assertIsInstance(mounts.get("https://"), httpx.HTTPTransport)

    def test_lowercase_env_vars_are_honoured(self):
        val = self._get("https://", https_proxy=self.PROXY)
        self.assertIsInstance(val, httpx.HTTPTransport)

    def test_loopback_always_bypassed(self):
        with _EnvOverride(HTTPS_PROXY=self.PROXY):
            mounts = build_httpx_mounts()
        for host in ("localhost", "127.0.0.1", "[::1]"):
            self.assertIsNone(mounts.get(f"https://{host}"), host)
            self.assertIsNone(mounts.get(f"http://{host}"), host)


# ---------------------------------------------------------------------------
# NO_PROXY bypass
# ---------------------------------------------------------------------------


class TestNoProxyBypass(unittest.TestCase):
    """Hosts listed in NO_PROXY must receive a None (direct) entry."""

    PROXY = "http://proxy.company.local:3128"

    def test_exact_hostname_bypassed(self):
        with _EnvOverride(HTTPS_PROXY=self.PROXY, NO_PROXY="internal.corp"):
            mounts = build_httpx_mounts()
        self.assertIsNone(mounts.get("https://internal.corp"))
        self.assertIsNone(mounts.get("http://internal.corp"))

    def test_wildcard_domain_bypassed(self):
        with _EnvOverride(HTTPS_PROXY=self.PROXY, NO_PROXY="*.corp.local"):
            mounts = build_httpx_mounts()
        # Wildcard is normalised to a leading dot
        self.assertIsNone(mounts.get("https://.corp.local"))
        self.assertIsNone(mounts.get("http://.corp.local"))

    def test_multiple_no_proxy_entries(self):
        no_proxy = "localhost,127.0.0.1,internal.corp,*.corp.local"
        with _EnvOverride(HTTPS_PROXY=self.PROXY, NO_PROXY=no_proxy):
            mounts = build_httpx_mounts()
        self.assertIsNone(mounts.get("https://localhost"))
        self.assertIsNone(mounts.get("https://127.0.0.1"))
        self.assertIsNone(mounts.get("https://internal.corp"))
        self.assertIsNone(mounts.get("https://.corp.local"))

    def test_cidr_notation_does_not_crash(self):
        """CIDR tokens are skipped gracefully (not expressible as URL prefixes)."""
        with _EnvOverride(HTTPS_PROXY=self.PROXY, NO_PROXY="10.0.0.0/8,*.corp.local"):
            mounts = build_httpx_mounts()
        # CIDR must not appear as a key
        cidr_keys = [k for k in mounts if "10.0.0.0/8" in k]
        self.assertEqual(cidr_keys, [])
        # Wildcard still added
        self.assertIsNone(mounts.get("https://.corp.local"))

    def test_bypass_takes_precedence_over_proxy_catchall(self):
        """Bypass (None) and catch-all proxy must both be present."""
        with _EnvOverride(HTTPS_PROXY=self.PROXY, NO_PROXY="internal.corp"):
            mounts = build_httpx_mounts()
        self.assertIsNone(mounts.get("https://internal.corp"))
        self.assertIsInstance(mounts.get("https://"), httpx.HTTPTransport)


# ---------------------------------------------------------------------------
# Integration: httpx.Client accepts the mounts map
# ---------------------------------------------------------------------------


class TestHttpxClientAcceptsMountsMap(unittest.TestCase):
    """Smoke-test: httpx.Client must be constructable with the returned map."""

    def test_client_construction_with_proxy(self):
        proxy = "http://proxy.company.local:3128"
        with _EnvOverride(HTTP_PROXY=proxy, HTTPS_PROXY=proxy,
                          NO_PROXY="localhost,127.0.0.1"):
            mounts = build_httpx_mounts()
        with httpx.Client(mounts=mounts) as client:
            self.assertIsNotNone(client)

    def test_client_construction_without_proxy(self):
        with _EnvOverride():
            mounts = build_httpx_mounts()
        self.assertEqual(mounts, {})
        with httpx.Client(mounts=mounts) as client:
            self.assertIsNotNone(client)


# ---------------------------------------------------------------------------
# _parse_no_proxy helper
# ---------------------------------------------------------------------------


class TestParseNoProxy(unittest.TestCase):
    def test_empty_string_returns_empty_list(self):
        with _EnvOverride(NO_PROXY=""):
            self.assertEqual(_parse_no_proxy(), [])

    def test_splits_on_comma(self):
        with _EnvOverride(NO_PROXY="a,b,c"):
            self.assertEqual(_parse_no_proxy(), ["a", "b", "c"])

    def test_strips_whitespace(self):
        with _EnvOverride(NO_PROXY=" a , b , c "):
            self.assertEqual(_parse_no_proxy(), ["a", "b", "c"])

    def test_ignores_empty_tokens(self):
        with _EnvOverride(NO_PROXY="a,,b"):
            self.assertEqual(_parse_no_proxy(), ["a", "b"])


# ---------------------------------------------------------------------------
# _no_proxy_to_httpx_key helper
# ---------------------------------------------------------------------------


class TestNoProxyToHttpxKey(unittest.TestCase):
    def test_plain_hostname(self):
        self.assertEqual(_no_proxy_to_httpx_key("internal.corp"), "internal.corp")

    def test_wildcard_converted_to_leading_dot(self):
        self.assertEqual(_no_proxy_to_httpx_key("*.corp.local"), ".corp.local")

    def test_ipv4_address_returned_as_is(self):
        self.assertEqual(_no_proxy_to_httpx_key("192.168.1.1"), "192.168.1.1")

    def test_ipv6_address_gets_brackets(self):
        self.assertEqual(_no_proxy_to_httpx_key("::1"), "[::1]")

    def test_cidr_returns_none(self):
        self.assertIsNone(_no_proxy_to_httpx_key("10.0.0.0/8"))
        self.assertIsNone(_no_proxy_to_httpx_key("192.168.0.0/16"))


if __name__ == "__main__":
    unittest.main()
