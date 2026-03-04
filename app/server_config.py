"""Configurable HTTP server timeouts.

Three env vars control connection and request behaviour:

REQUEST_TIMEOUT   – Maximum wall-clock time (seconds) allowed for a single
                    HTTP request, measured from when the request starts until
                    the response is fully sent.  Enforced by
                    RequestTimeoutMiddleware using asyncio.wait_for().
                    Set to 0 to disable (default: 30).

IDLE_TIMEOUT      – Maximum time (seconds) a Keep-Alive connection may sit
                    idle between requests.  Maps to uvicorn's
                    ``timeout_keep_alive`` parameter.  When KEEPALIVE_TIMEOUT
                    is also set, KEEPALIVE_TIMEOUT takes priority.
                    (default: 65)

KEEPALIVE_TIMEOUT – Same semantic as IDLE_TIMEOUT but named after the HTTP
                    Keep-Alive header convention.  Takes priority over
                    IDLE_TIMEOUT when both are set.  Maps to uvicorn's
                    ``timeout_keep_alive``.
                    (default: 75)

Safe defaults for common reverse proxies / CDNs
------------------------------------------------
Proxy            keepalive origin   idle origin
Cloudflare       400 s              90 s
Traefik          --                 90 s (idleConnTimeout)
F5 BIG-IP        300 s              300 s

Defaults are intentionally below Cloudflare's 90 s idle and well below the
400 s keepalive, so the *server* always closes idle connections first.  This
prevents the proxy from reusing a half-closed TCP connection and avoids
502/504 errors caused by race conditions on the server side.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Callable, Dict

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_REQUEST_TIMEOUT: int = 30   # seconds; 0 = disabled
_DEFAULT_IDLE_TIMEOUT: int = 65      # seconds; mapped to uvicorn keepalive
_DEFAULT_KEEPALIVE_TIMEOUT: int = 75 # seconds; mapped to uvicorn keepalive


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_nonneg_int(raw: str, default: int, name: str) -> int:
    """Parse *raw* as a non-negative integer, falling back to *default*."""
    raw = raw.strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        _logger.warning("server_config: %s=%r is not an integer; using default %d", name, raw, default)
        return default
    if value < 0:
        _logger.warning("server_config: %s=%d is negative; using default %d", name, value, default)
        return default
    return value


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------


def get_request_timeout() -> int:
    """Return REQUEST_TIMEOUT in seconds (0 = disabled)."""
    return _parse_nonneg_int(
        os.environ.get("REQUEST_TIMEOUT", ""),
        _DEFAULT_REQUEST_TIMEOUT,
        "REQUEST_TIMEOUT",
    )


def get_keepalive_timeout() -> int:
    """Return the effective keepalive timeout in seconds.

    Priority: KEEPALIVE_TIMEOUT > IDLE_TIMEOUT > built-in default (75 s).
    """
    kp_raw = os.environ.get("KEEPALIVE_TIMEOUT", "").strip()
    if kp_raw:
        return _parse_nonneg_int(kp_raw, _DEFAULT_KEEPALIVE_TIMEOUT, "KEEPALIVE_TIMEOUT")

    idle_raw = os.environ.get("IDLE_TIMEOUT", "").strip()
    if idle_raw:
        return _parse_nonneg_int(idle_raw, _DEFAULT_IDLE_TIMEOUT, "IDLE_TIMEOUT")

    return _DEFAULT_KEEPALIVE_TIMEOUT


def get_uvicorn_kwargs() -> Dict[str, Any]:
    """Return uvicorn.run() keyword arguments derived from timeout env vars.

    Pass the result as **kwargs to uvicorn.run() in the app entrypoints so
    that timeout settings take effect without duplicating the parsing logic.

    Example::

        import uvicorn
        from app.server_config import get_uvicorn_kwargs

        uvicorn.run("app.honeypot_public:app", host="0.0.0.0", port=8000,
                    **get_uvicorn_kwargs())
    """
    return {
        "timeout_keep_alive": get_keepalive_timeout(),
    }


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------


class RequestTimeoutMiddleware:
    """ASGI middleware: cancel requests that exceed REQUEST_TIMEOUT seconds.

    Implemented at the raw ASGI level (not Starlette BaseHTTPMiddleware) so
    it wraps the complete request-response cycle including streaming bodies.

    Behaviour:
    - If the timeout fires *before* response headers are sent: returns a
      JSON ``408 Request Timeout`` response.
    - If the timeout fires *after* headers have already been sent: the
      inner coroutine is cancelled and the connection closes; no second
      response attempt is made.
    - Non-HTTP scopes (websocket, lifespan) pass through unchanged.
    - timeout == 0: middleware is a transparent no-op.
    """

    def __init__(self, app: Callable, timeout: float) -> None:
        self.app = app
        self.timeout = float(timeout)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or self.timeout <= 0:
            await self.app(scope, receive, send)
            return

        response_started = False

        async def _send(message: dict) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await asyncio.wait_for(
                self.app(scope, receive, _send),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            _logger.warning(
                "server_config: request timeout (%.0fs) for %s %s",
                self.timeout,
                scope.get("method", "?"),
                scope.get("path", "?"),
            )
            if not response_started:
                body = b'{"detail":"Request Timeout"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 408,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
