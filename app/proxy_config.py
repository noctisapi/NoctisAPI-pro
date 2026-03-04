"""Corporate egress proxy support for outbound HTTP/HTTPS requests.

Reads HTTP_PROXY, HTTPS_PROXY, and NO_PROXY from the environment and
builds an httpx-compatible ``mounts`` map.  When no proxy is configured
the returned dict is empty, so existing httpx.Client() call sites are
not affected.

urllib.request (used by honey_licensing/client.py and panel_mvp.py)
automatically honours HTTP_PROXY / HTTPS_PROXY / NO_PROXY from the
environment via its default ProxyHandler — no changes are needed there.

Proxy key format recognised by httpx mounts
-------------------------------------------
* ``"http://"``              – all HTTP traffic
* ``"https://"``             – all HTTPS traffic
* ``"https://hostname"``     – exact host (both schemes)
* ``"https://.example.com"`` – any subdomain of example.com
* ``None`` value             – direct connection (bypass proxy)

CIDR ranges in NO_PROXY (e.g. ``10.0.0.0/8``) are skipped here because
httpx URL-pattern keys do not support CIDR notation; urllib handles them
natively through its ProxyHandler.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
from typing import Any, Dict, Optional

import httpx


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _read_env(name: str) -> Optional[str]:
    """Return the value of *name* or its lowercase variant, or None."""
    return (os.environ.get(name) or os.environ.get(name.lower()) or "").strip() or None


def _parse_no_proxy() -> list[str]:
    """Return a list of non-empty NO_PROXY tokens."""
    raw = _read_env("NO_PROXY") or ""
    return [t.strip() for t in raw.split(",") if t.strip()]


def _is_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        # ip_network accepts plain IPs (e.g. "127.0.0.1") — only flag CIDR
        # blocks that contain a prefix length.
        return "/" in token
    except ValueError:
        return False


def _no_proxy_to_httpx_key(token: str) -> Optional[str]:
    """Convert a single NO_PROXY token to an httpx URL-prefix host key.

    Returns None for tokens that cannot be represented as a URL prefix
    (i.e. bare CIDR blocks).
    """
    if _is_cidr(token):
        return None

    # Normalise wildcard prefix: "*.corp.local" → ".corp.local"
    # httpx interprets a leading dot as "any subdomain of this domain".
    key = token.lstrip("*")

    # IPv6 addresses must be bracketed in URLs: ::1 → [::1]
    try:
        addr = ipaddress.ip_address(key)
        if addr.version == 6:
            key = f"[{key}]"
    except ValueError:
        pass

    return key or None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_httpx_mounts(
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Dict[str, Any]:
    """Return a ``mounts`` map for use as ``httpx.Client(mounts=...)``.

    When HTTP_PROXY and HTTPS_PROXY are both unset the function returns
    an empty dict, which leaves httpx's default behaviour intact.

    With a proxy configured:
    * All HTTP traffic is routed through HTTP_PROXY.
    * All HTTPS traffic is routed through HTTPS_PROXY (using CONNECT
      tunnelling, which httpx/httpcore handle automatically).
    * *ssl_context* is forwarded to each ``HTTPTransport`` so that the
      custom CA trust store is used for proxy CONNECT handshakes too.
    * TLS certificate verification is never disabled.
    * Hosts listed in NO_PROXY receive a ``None`` entry (direct
      connection), taking precedence over the catch-all proxy entries.
    * ``localhost``, ``127.0.0.1``, and ``[::1]`` are always bypassed,
      even when not listed in NO_PROXY.
    """
    http_proxy = _read_env("HTTP_PROXY")
    https_proxy = _read_env("HTTPS_PROXY")

    if not http_proxy and not https_proxy:
        return {}

    verify: Any = ssl_context if ssl_context is not None else True

    mounts: Dict[str, Any] = {}

    # --- NO_PROXY bypasses (more-specific patterns beat the catch-alls) ---
    for token in _parse_no_proxy():
        key = _no_proxy_to_httpx_key(token)
        if key is None:
            continue  # CIDR ranges are not expressible as URL-prefix keys
        mounts[f"http://{key}"] = None
        mounts[f"https://{key}"] = None

    # Always bypass loopback regardless of NO_PROXY content.
    for host in ("localhost", "127.0.0.1", "[::1]"):
        mounts.setdefault(f"http://{host}", None)
        mounts.setdefault(f"https://{host}", None)

    # --- Catch-all proxy entries (least specific, applied last) ---
    if http_proxy:
        mounts["http://"] = httpx.HTTPTransport(proxy=http_proxy, verify=verify)
    if https_proxy:
        mounts["https://"] = httpx.HTTPTransport(proxy=https_proxy, verify=verify)

    return mounts
