"""Reverse proxy compatibility — public base URL resolution.

Determines the effective public base URL for outgoing links, OpenAPI
servers, and redirects using (in priority order):

  1. PUBLIC_BASE_URL env var — static override, highest priority.
  2. X-Forwarded-Proto / X-Forwarded-Host / X-Forwarded-Port headers —
     only honoured when the direct TCP peer is in the configured trusted
     proxy networks (see app.trusted_proxy).
  3. request.base_url — raw socket information, used for direct access.

Also provides ReverseProxyMiddleware: a lightweight ASGI middleware that
rewrites scope["scheme"] and scope["server"] from forwarded headers so
that Starlette's built-in URL helpers (request.base_url, url_for(),
RedirectResponse) automatically reflect the correct public URL without
any per-handler changes.

Configuration
-------------
Set PUBLIC_BASE_URL to an absolute URL without a trailing slash:

    PUBLIC_BASE_URL=https://api.company.com

When set, forwarding headers are ignored for URL generation (the static
value wins).  When unset, the middleware derives the public URL from
forwarded headers (for trusted proxies) or from the raw socket
(direct access).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Callable, Optional, Tuple

from fastapi import Request

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static configuration
# ---------------------------------------------------------------------------

_PUBLIC_BASE_URL: str = (os.environ.get("PUBLIC_BASE_URL") or "").strip().rstrip("/")

_PORT_RE = re.compile(r"^\d+$")


def get_static_public_base_url() -> str:
    """Return the PUBLIC_BASE_URL env var, or empty string if unset."""
    return _PUBLIC_BASE_URL


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------


def _parse_host_header(value: str) -> Tuple[str, Optional[int]]:
    """Parse 'host[:port]' into (host, port_or_None).

    Handles bracketed IPv6 (e.g. ``[::1]:8080``).
    """
    value = value.strip()
    if value.startswith("["):
        # IPv6 literal in brackets
        bracket_end = value.find("]")
        if bracket_end == -1:
            return value, None
        host = value[: bracket_end + 1]
        rest = value[bracket_end + 1 :]
        if rest.startswith(":") and _PORT_RE.match(rest[1:]):
            return host, int(rest[1:])
        return host, None
    if ":" in value:
        host, _, port_str = value.rpartition(":")
        if _PORT_RE.match(port_str):
            return host, int(port_str)
    return value, None


def _build_base_url(proto: str, host_hdr: str, port_hdr: str) -> str:
    """Construct a base URL string from parsed forwarded header values."""
    scheme = proto if proto in ("http", "https") else "http"
    default_port = 443 if scheme == "https" else 80

    if host_hdr:
        host, port = _parse_host_header(host_hdr)
    else:
        host, port = "localhost", None

    # Explicit X-Forwarded-Port overrides port derived from X-Forwarded-Host
    if port_hdr and _PORT_RE.match(port_hdr):
        port = int(port_hdr)

    if port is None or port == default_port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


# ---------------------------------------------------------------------------
# Internal: derive forwarded base URL
# ---------------------------------------------------------------------------


def _derive_forwarded_base_url(
    remote_addr: str,
    headers: dict,  # expects lowercase keys
    trusted_networks,
) -> Optional[str]:
    """Return base URL from forwarded headers if *remote_addr* is trusted.

    Returns ``None`` when the peer is untrusted or no forwarding headers
    are present, so the caller can fall back to the raw socket URL.
    """
    from app.trusted_proxy import _is_trusted  # local import avoids circular at top-level

    if not _is_trusted(remote_addr, trusted_networks):
        return None

    proto = (headers.get("x-forwarded-proto") or "").strip().lower()
    host_hdr = (headers.get("x-forwarded-host") or "").strip()
    port_hdr = (headers.get("x-forwarded-port") or "").strip()

    if not proto and not host_hdr:
        return None  # no relevant forwarding headers

    return _build_base_url(proto, host_hdr, port_hdr)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_public_base_url(request: Request) -> str:
    """Return the effective public base URL for this request (no trailing slash).

    Priority:

    1. ``PUBLIC_BASE_URL`` env var (static config).
    2. X-Forwarded-Proto/Host/Port headers, when the direct TCP peer is
       in the configured trusted proxy networks.
    3. ``str(request.base_url)`` stripped of trailing slash (direct access).
    """
    if _PUBLIC_BASE_URL:
        return _PUBLIC_BASE_URL

    from app.trusted_proxy import get_trusted_networks

    remote_addr: str = (
        request.client.host if request.client else None
    ) or "0.0.0.0"

    trusted = get_trusted_networks()
    headers_lower = {k.lower(): v for k, v in request.headers.items()}
    derived = _derive_forwarded_base_url(remote_addr, headers_lower, trusted)
    if derived:
        return derived

    return str(request.base_url).rstrip("/")


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------


def _rewrite_scope(scope: dict, headers: dict) -> dict:
    """Return a shallow copy of *scope* with scheme/server rewritten.

    *headers* must have lowercase keys.  Only modifies scope when at
    least one of X-Forwarded-Proto or X-Forwarded-Host is present.
    """
    proto = (headers.get("x-forwarded-proto") or "").strip().lower()
    host_hdr = (headers.get("x-forwarded-host") or "").strip()
    port_hdr = (headers.get("x-forwarded-port") or "").strip()

    if not proto and not host_hdr:
        return scope  # nothing to rewrite

    scope = dict(scope)  # shallow copy so original is not mutated

    if proto in ("http", "https"):
        scope["scheme"] = proto
        scheme = proto
    else:
        scheme = scope.get("scheme", "http")

    default_port = 443 if scheme == "https" else 80

    if host_hdr:
        host, port = _parse_host_header(host_hdr)
        # scope["server"] expects a bare host (no brackets for IPv6)
        bare_host = host.strip("[]")
    else:
        current_server = scope.get("server") or ("localhost", 80)
        bare_host = current_server[0]
        port = current_server[1]

    if port_hdr and _PORT_RE.match(port_hdr):
        port = int(port_hdr)

    if port is None:
        port = default_port

    scope["server"] = (bare_host, port)
    return scope


class ReverseProxyMiddleware:
    """ASGI middleware: rewrite scope scheme/server from forwarded headers.

    Modifies ``scope["scheme"]`` and ``scope["server"]`` before the
    request reaches Starlette, so that ``request.base_url``, ``url_for()``,
    and ``RedirectResponse`` automatically use the correct public URL.

    Headers are only honoured when the direct TCP peer falls within the
    configured trusted proxy networks (same configuration as
    ``app.trusted_proxy``).  When ``PUBLIC_BASE_URL`` is set, no rewriting
    is performed because the static URL takes priority.
    """

    def __init__(self, app: Callable) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Static PUBLIC_BASE_URL wins; skip dynamic scope rewriting
        if not _PUBLIC_BASE_URL:
            client = scope.get("client")
            remote_addr = client[0] if client else "0.0.0.0"

            from app.trusted_proxy import _is_trusted, get_trusted_networks

            trusted = get_trusted_networks()
            if _is_trusted(remote_addr, trusted):
                headers = {
                    k.decode(): v.decode()
                    for k, v in scope.get("headers", [])
                }
                scope = _rewrite_scope(scope, headers)

        await self.app(scope, receive, send)
