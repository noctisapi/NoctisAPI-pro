"""Tests for app.trusted_proxy — trusted proxy handling and client IP extraction.

Covers:
 - CIDR list parsing
 - Trusted-network cache and env-var override
 - Per-IP trust evaluation
 - X-Forwarded-For rightmost-non-trusted walk
 - resolve_client_ip() — core behaviour matrix:
     * trusted proxy with XFF / CF-Connecting-IP / X-Real-IP
     * untrusted source with forged headers (spoofing prevention)
     * header priority order
     * fallback to remote_addr
"""

from __future__ import annotations

import ipaddress
import logging
import os
import unittest
from unittest.mock import patch

from fastapi import Request

from app.trusted_proxy import (
    _first_untrusted_from_xff,
    _is_trusted,
    _parse_cidr_list,
    _reset_cache,
    get_trusted_networks,
    resolve_client_ip,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _req(remote: str, **headers: str) -> Request:
    """Build a minimal Starlette Request with the given remote IP and headers."""
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
    }
    return Request(scope)


class _EnvOverride:
    """Context manager: set env vars, restore originals on exit."""

    def __init__(self, **kwargs: str | None):
        self._overrides = kwargs
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self._overrides}
        for k in self._overrides:
            os.environ.pop(k, None)
        for k, v in self._overrides.items():
            if v is not None:
                os.environ[k] = v
        _reset_cache()
        return self

    def __exit__(self, *_):
        for k in self._overrides:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v
        _reset_cache()


# Short-hand networks used across multiple tests
_PRIVATE = _parse_cidr_list("10.0.0.0/8 127.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ::1/128")
_CF = _parse_cidr_list("173.245.48.0/20 103.21.244.0/22")
_PROXY_AND_PRIVATE = _parse_cidr_list(
    "10.0.0.0/8 127.0.0.0/8 172.16.0.0/12 192.168.0.0/16 173.245.48.0/20 103.21.244.0/22"
)


# ---------------------------------------------------------------------------
# _parse_cidr_list
# ---------------------------------------------------------------------------


class TestParseCidrList(unittest.TestCase):
    def test_single_cidr(self):
        nets = _parse_cidr_list("10.0.0.0/8")
        self.assertEqual(len(nets), 1)
        self.assertIsInstance(nets[0], ipaddress.IPv4Network)

    def test_comma_separated(self):
        nets = _parse_cidr_list("10.0.0.0/8,172.16.0.0/12")
        self.assertEqual(len(nets), 2)

    def test_newline_separated(self):
        nets = _parse_cidr_list("10.0.0.0/8\n172.16.0.0/12")
        self.assertEqual(len(nets), 2)

    def test_mixed_separators(self):
        nets = _parse_cidr_list("10.0.0.0/8, 172.16.0.0/12\n192.168.0.0/16")
        self.assertEqual(len(nets), 3)

    def test_ipv6_cidr(self):
        nets = _parse_cidr_list("::1/128 fc00::/7")
        self.assertEqual(len(nets), 2)

    def test_invalid_token_skipped(self):
        nets = _parse_cidr_list("10.0.0.0/8 not-a-cidr 172.16.0.0/12")
        self.assertEqual(len(nets), 2)

    def test_empty_string_returns_empty_list(self):
        self.assertEqual(_parse_cidr_list(""), [])


# ---------------------------------------------------------------------------
# get_trusted_networks
# ---------------------------------------------------------------------------


class TestGetTrustedNetworks(unittest.TestCase):
    def test_default_includes_loopback(self):
        with _EnvOverride(TRUSTED_PROXIES=None):
            nets = get_trusted_networks()
        loopback = ipaddress.ip_address("127.0.0.1")
        self.assertTrue(any(loopback in n for n in nets))

    def test_default_includes_rfc1918(self):
        with _EnvOverride(TRUSTED_PROXIES=None):
            nets = get_trusted_networks()
        private = ipaddress.ip_address("10.10.10.10")
        self.assertTrue(any(private in n for n in nets))

    def test_custom_replaces_defaults(self):
        with _EnvOverride(TRUSTED_PROXIES="203.0.113.0/24"):
            nets = get_trusted_networks()
        # Only the custom CIDR — loopback should NOT be trusted
        loopback = ipaddress.ip_address("127.0.0.1")
        self.assertFalse(any(loopback in n for n in nets))
        custom = ipaddress.ip_address("203.0.113.1")
        self.assertTrue(any(custom in n for n in nets))


# ---------------------------------------------------------------------------
# _is_trusted
# ---------------------------------------------------------------------------


class TestIsTrusted(unittest.TestCase):
    def test_ip_in_network_is_trusted(self):
        self.assertTrue(_is_trusted("10.0.0.1", _PRIVATE))

    def test_ip_outside_network_is_not_trusted(self):
        self.assertFalse(_is_trusted("203.0.113.1", _PRIVATE))

    def test_loopback_is_trusted_by_default(self):
        self.assertTrue(_is_trusted("127.0.0.1", _PRIVATE))

    def test_ipv6_loopback(self):
        self.assertTrue(_is_trusted("::1", _PRIVATE))

    def test_cloudflare_ip_trusted_when_cf_in_list(self):
        self.assertTrue(_is_trusted("173.245.48.1", _CF))

    def test_invalid_ip_returns_false(self):
        self.assertFalse(_is_trusted("not-an-ip", _PRIVATE))

    def test_public_ip_not_trusted_by_private_list(self):
        self.assertFalse(_is_trusted("8.8.8.8", _PRIVATE))


# ---------------------------------------------------------------------------
# _first_untrusted_from_xff
# ---------------------------------------------------------------------------


class TestFirstUntrustedFromXff(unittest.TestCase):
    def test_single_untrusted_ip(self):
        result = _first_untrusted_from_xff("203.0.113.5", _PRIVATE)
        self.assertEqual(result, "203.0.113.5")

    def test_client_then_proxy(self):
        # XFF: <client>, <proxy>  → client is rightmost non-trusted
        result = _first_untrusted_from_xff("203.0.113.5, 10.0.0.1", _PRIVATE)
        self.assertEqual(result, "203.0.113.5")

    def test_client_then_two_proxies(self):
        result = _first_untrusted_from_xff("203.0.113.5, 10.0.0.1, 127.0.0.1", _PRIVATE)
        self.assertEqual(result, "203.0.113.5")

    def test_all_trusted_returns_leftmost(self):
        # Fully internal chain → leftmost is the origin
        result = _first_untrusted_from_xff("10.0.0.2, 10.0.0.3, 127.0.0.1", _PRIVATE)
        self.assertEqual(result, "10.0.0.2")

    def test_forged_prefix_rightmost_non_trusted_returned(self):
        # Attacker prepends a fake IP; the last non-trusted entry is real client.
        result = _first_untrusted_from_xff("fake-attacker, 203.0.113.5, 10.0.0.1", _PRIVATE)
        # "fake-attacker" is not a valid IP so it's skipped; 203.0.113.5 is returned
        self.assertEqual(result, "203.0.113.5")

    def test_empty_string_returns_none(self):
        self.assertIsNone(_first_untrusted_from_xff("", _PRIVATE))


# ---------------------------------------------------------------------------
# resolve_client_ip — core behaviour
# ---------------------------------------------------------------------------


class TestResolveClientIpTrustedProxy(unittest.TestCase):
    """Requests arriving from a trusted proxy: headers are honoured."""

    def _resolve(self, remote: str, **headers: str) -> str:
        with patch("app.trusted_proxy.get_trusted_networks", return_value=_PROXY_AND_PRIVATE):
            return resolve_client_ip(_req(remote, **headers))

    # --- XFF ---------------------------------------------------------------

    def test_trusted_proxy_xff_returns_client_ip(self):
        """Request from trusted proxy (10.x) with XFF — extracts client IP."""
        ip = self._resolve("10.0.0.1", x_forwarded_for="203.0.113.42")
        self.assertEqual(ip, "203.0.113.42")

    def test_trusted_proxy_xff_multi_hop(self):
        """Multi-hop XFF: rightmost non-trusted IP is returned."""
        ip = self._resolve("10.0.0.1", x_forwarded_for="203.0.113.42, 10.0.0.2")
        self.assertEqual(ip, "203.0.113.42")

    def test_trusted_proxy_xff_strips_whitespace(self):
        ip = self._resolve("10.0.0.1", x_forwarded_for="  203.0.113.42  , 10.0.0.2")
        self.assertEqual(ip, "203.0.113.42")

    # --- CF-Connecting-IP --------------------------------------------------

    def test_cf_connecting_ip_takes_priority_over_xff(self):
        """CF-Connecting-IP is returned before XFF when CF is a trusted proxy."""
        ip = self._resolve(
            "173.245.48.1",
            cf_connecting_ip="198.51.100.7",
            x_forwarded_for="203.0.113.42",
        )
        self.assertEqual(ip, "198.51.100.7")

    def test_cf_connecting_ip_from_trusted_proxy(self):
        ip = self._resolve("173.245.48.1", cf_connecting_ip="198.51.100.77")
        self.assertEqual(ip, "198.51.100.77")

    # --- X-Real-IP ---------------------------------------------------------

    def test_x_real_ip_used_when_no_xff(self):
        ip = self._resolve("10.0.0.1", x_real_ip="203.0.113.99")
        self.assertEqual(ip, "203.0.113.99")

    def test_xff_takes_priority_over_x_real_ip(self):
        ip = self._resolve(
            "10.0.0.1",
            x_forwarded_for="203.0.113.42",
            x_real_ip="203.0.113.99",
        )
        self.assertEqual(ip, "203.0.113.42")

    # --- Fallback ----------------------------------------------------------

    def test_no_headers_returns_remote_addr(self):
        ip = self._resolve("10.0.0.1")
        self.assertEqual(ip, "10.0.0.1")

    def test_loopback_proxy_xff(self):
        ip = self._resolve("127.0.0.1", x_forwarded_for="203.0.113.1")
        self.assertEqual(ip, "203.0.113.1")


# ---------------------------------------------------------------------------
# resolve_client_ip — spoofing prevention
# ---------------------------------------------------------------------------


class TestResolveClientIpUntrustedSource(unittest.TestCase):
    """Requests from untrusted sources: all forwarding headers are ignored."""

    def _resolve(self, remote: str, **headers: str) -> str:
        with patch("app.trusted_proxy.get_trusted_networks", return_value=_PRIVATE):
            return resolve_client_ip(_req(remote, **headers))

    def test_untrusted_xff_ignored(self):
        """Forged X-Forwarded-For from a public IP is discarded."""
        ip = self._resolve("203.0.113.1", x_forwarded_for="1.1.1.1")
        self.assertEqual(ip, "203.0.113.1")

    def test_untrusted_cf_connecting_ip_ignored(self):
        ip = self._resolve("203.0.113.1", cf_connecting_ip="8.8.8.8")
        self.assertEqual(ip, "203.0.113.1")

    def test_untrusted_x_real_ip_ignored(self):
        ip = self._resolve("203.0.113.1", x_real_ip="8.8.8.8")
        self.assertEqual(ip, "203.0.113.1")

    def test_untrusted_all_headers_ignored(self):
        """Even when multiple forged headers are sent, direct IP is used."""
        ip = self._resolve(
            "203.0.113.1",
            x_forwarded_for="192.0.2.1",
            x_real_ip="192.0.2.2",
            cf_connecting_ip="192.0.2.3",
        )
        self.assertEqual(ip, "203.0.113.1")

    def test_untrusted_emits_warning(self):
        """A warning must be logged when forged headers are detected."""
        with self.assertLogs("app.trusted_proxy", level=logging.WARNING) as cm:
            self._resolve("203.0.113.1", x_forwarded_for="1.1.1.1")
        self.assertTrue(any("untrusted" in msg.lower() for msg in cm.output))

    def test_trusted_ip_xff_still_honoured(self):
        """A private-range IP is trusted even without explicit TRUSTED_PROXIES."""
        ip = self._resolve("10.0.0.1", x_forwarded_for="198.51.100.5")
        self.assertEqual(ip, "198.51.100.5")

    def test_no_client_falls_back_to_0000(self):
        """Missing client info (rare) falls back to 0.0.0.0."""
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [],
            "client": None,
        }
        req = Request(scope)
        with patch("app.trusted_proxy.get_trusted_networks", return_value=_PRIVATE):
            ip = resolve_client_ip(req)
        self.assertEqual(ip, "0.0.0.0")


# ---------------------------------------------------------------------------
# Priority order — full chain
# ---------------------------------------------------------------------------


class TestHeaderPriority(unittest.TestCase):
    """Verify the documented priority: CF > XFF > X-Real-IP > remote_addr."""

    def _resolve(self, remote: str, **headers: str) -> str:
        # Use a network that includes both private and Cloudflare ranges
        with patch("app.trusted_proxy.get_trusted_networks", return_value=_PROXY_AND_PRIVATE):
            return resolve_client_ip(_req(remote, **headers))

    def test_cf_beats_xff_and_xri(self):
        ip = self._resolve(
            "173.245.48.1",
            cf_connecting_ip="1.1.1.1",
            x_forwarded_for="2.2.2.2",
            x_real_ip="3.3.3.3",
        )
        self.assertEqual(ip, "1.1.1.1")

    def test_xff_beats_xri(self):
        ip = self._resolve(
            "10.0.0.1",
            x_forwarded_for="2.2.2.2",
            x_real_ip="3.3.3.3",
        )
        self.assertEqual(ip, "2.2.2.2")

    def test_xri_beats_remote(self):
        ip = self._resolve("10.0.0.1", x_real_ip="3.3.3.3")
        self.assertEqual(ip, "3.3.3.3")

    def test_remote_when_no_headers(self):
        ip = self._resolve("10.0.0.1")
        self.assertEqual(ip, "10.0.0.1")


# ---------------------------------------------------------------------------
# TRUSTED_PROXIES env-var integration
# ---------------------------------------------------------------------------


class TestTrustedProxiesEnvVar(unittest.TestCase):
    def test_custom_trusted_proxies_controls_header_trust(self):
        """When TRUSTED_PROXIES is set, only those CIDRs trust headers."""
        # 198.51.100.0/24 is the only trusted range
        with _EnvOverride(TRUSTED_PROXIES="198.51.100.0/24"):
            # From a trusted proxy → XFF is honoured
            trusted_ip = resolve_client_ip(
                _req("198.51.100.1", x_forwarded_for="203.0.113.5")
            )
            # From an untrusted source → XFF is ignored
            untrusted_ip = resolve_client_ip(
                _req("203.0.113.1", x_forwarded_for="8.8.8.8")
            )

        self.assertEqual(trusted_ip, "203.0.113.5")
        self.assertEqual(untrusted_ip, "203.0.113.1")

    def test_cloudflare_cidrs_allow_cf_header(self):
        with _EnvOverride(TRUSTED_PROXIES="173.245.48.0/20,103.21.244.0/22"):
            ip = resolve_client_ip(
                _req("173.245.48.1", cf_connecting_ip="198.51.100.99")
            )
        self.assertEqual(ip, "198.51.100.99")

    def test_cloudflare_cidrs_block_non_cf_xff(self):
        """A public IP outside the trusted CF range cannot inject headers."""
        with _EnvOverride(TRUSTED_PROXIES="173.245.48.0/20"):
            ip = resolve_client_ip(
                _req("8.8.8.8", x_forwarded_for="198.51.100.99")
            )
        self.assertEqual(ip, "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
