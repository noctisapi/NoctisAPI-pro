"""Tests for app.server_config — HTTP server timeout configuration.

Covers:
 - get_request_timeout(): env var parsing, validation, defaults
 - get_keepalive_timeout(): KEEPALIVE_TIMEOUT > IDLE_TIMEOUT > default priority
 - get_uvicorn_kwargs(): returns dict with timeout_keep_alive key
 - RequestTimeoutMiddleware:
     * passes through when timeout is 0 (disabled)
     * passes through non-http scopes unchanged
     * allows fast requests through unmodified
     * cancels slow requests and returns 408 before headers are sent
     * does not send 408 when headers already started (partial response)
     * logs a warning on timeout
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import unittest

from app.server_config import (
    RequestTimeoutMiddleware,
    get_keepalive_timeout,
    get_request_timeout,
    get_uvicorn_kwargs,
    _DEFAULT_KEEPALIVE_TIMEOUT,
    _DEFAULT_IDLE_TIMEOUT,
    _DEFAULT_REQUEST_TIMEOUT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _EnvOverride:
    _VARS = ("REQUEST_TIMEOUT", "KEEPALIVE_TIMEOUT", "IDLE_TIMEOUT")

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


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_scope(path: str = "/") -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 0),
        "server": ("localhost", 8000),
        "scheme": "http",
    }


# ---------------------------------------------------------------------------
# get_request_timeout()
# ---------------------------------------------------------------------------


class TestGetRequestTimeout(unittest.TestCase):

    def test_default_when_unset(self):
        with _EnvOverride():
            self.assertEqual(get_request_timeout(), _DEFAULT_REQUEST_TIMEOUT)

    def test_reads_env_var(self):
        with _EnvOverride(REQUEST_TIMEOUT="60"):
            self.assertEqual(get_request_timeout(), 60)

    def test_zero_is_valid(self):
        with _EnvOverride(REQUEST_TIMEOUT="0"):
            self.assertEqual(get_request_timeout(), 0)

    def test_invalid_string_returns_default(self):
        with _EnvOverride(REQUEST_TIMEOUT="notanumber"):
            self.assertEqual(get_request_timeout(), _DEFAULT_REQUEST_TIMEOUT)

    def test_negative_returns_default(self):
        with _EnvOverride(REQUEST_TIMEOUT="-5"):
            self.assertEqual(get_request_timeout(), _DEFAULT_REQUEST_TIMEOUT)

    def test_whitespace_stripped(self):
        with _EnvOverride(REQUEST_TIMEOUT="  45  "):
            self.assertEqual(get_request_timeout(), 45)


# ---------------------------------------------------------------------------
# get_keepalive_timeout()
# ---------------------------------------------------------------------------


class TestGetKeepaliveTimeout(unittest.TestCase):

    def test_default_when_nothing_set(self):
        with _EnvOverride():
            self.assertEqual(get_keepalive_timeout(), _DEFAULT_KEEPALIVE_TIMEOUT)

    def test_keepalive_timeout_is_used(self):
        with _EnvOverride(KEEPALIVE_TIMEOUT="90"):
            self.assertEqual(get_keepalive_timeout(), 90)

    def test_idle_timeout_used_as_fallback(self):
        with _EnvOverride(IDLE_TIMEOUT="60"):
            self.assertEqual(get_keepalive_timeout(), 60)

    def test_keepalive_takes_priority_over_idle(self):
        with _EnvOverride(KEEPALIVE_TIMEOUT="90", IDLE_TIMEOUT="60"):
            self.assertEqual(get_keepalive_timeout(), 90)

    def test_invalid_keepalive_returns_default(self):
        with _EnvOverride(KEEPALIVE_TIMEOUT="bad"):
            self.assertEqual(get_keepalive_timeout(), _DEFAULT_KEEPALIVE_TIMEOUT)

    def test_invalid_idle_returns_idle_default(self):
        with _EnvOverride(IDLE_TIMEOUT="bad"):
            self.assertEqual(get_keepalive_timeout(), _DEFAULT_IDLE_TIMEOUT)

    def test_whitespace_stripped(self):
        with _EnvOverride(KEEPALIVE_TIMEOUT="  120  "):
            self.assertEqual(get_keepalive_timeout(), 120)


# ---------------------------------------------------------------------------
# get_uvicorn_kwargs()
# ---------------------------------------------------------------------------


class TestGetUvicornKwargs(unittest.TestCase):

    def test_returns_dict(self):
        with _EnvOverride():
            result = get_uvicorn_kwargs()
        self.assertIsInstance(result, dict)

    def test_timeout_keep_alive_present(self):
        with _EnvOverride(KEEPALIVE_TIMEOUT="90"):
            result = get_uvicorn_kwargs()
        self.assertIn("timeout_keep_alive", result)
        self.assertEqual(result["timeout_keep_alive"], 90)

    def test_timeout_keep_alive_uses_default(self):
        with _EnvOverride():
            result = get_uvicorn_kwargs()
        self.assertEqual(result["timeout_keep_alive"], _DEFAULT_KEEPALIVE_TIMEOUT)


# ---------------------------------------------------------------------------
# RequestTimeoutMiddleware
# ---------------------------------------------------------------------------


class TestRequestTimeoutMiddlewareDisabled(unittest.TestCase):
    """When timeout == 0 the middleware is a transparent no-op."""

    def test_passes_through_when_timeout_zero(self):
        called = []

        async def inner(scope, receive, send):
            called.append(True)

        async def go():
            mw = RequestTimeoutMiddleware(inner, timeout=0)
            await mw(_make_scope(), None, None)

        _run(go())
        self.assertEqual(called, [True])

    def test_non_http_scope_passes_through(self):
        called = []

        async def inner(scope, receive, send):
            called.append(scope["type"])

        async def go():
            mw = RequestTimeoutMiddleware(inner, timeout=5)
            await mw({"type": "lifespan"}, None, None)

        _run(go())
        self.assertEqual(called, ["lifespan"])


class TestRequestTimeoutMiddlewareFastRequest(unittest.TestCase):
    """Fast requests pass through and produce the correct response."""

    def test_fast_request_not_cancelled(self):
        messages = []

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def _collect(msg):
            messages.append(msg)

        async def go():
            mw = RequestTimeoutMiddleware(inner, timeout=10)
            await mw(_make_scope(), None, _collect)

        _run(go())
        statuses = [m["status"] for m in messages if m["type"] == "http.response.start"]
        self.assertEqual(statuses, [200])

    def test_response_body_forwarded(self):
        messages = []

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"hello"})

        async def _collect(msg):
            messages.append(msg)

        async def go():
            mw = RequestTimeoutMiddleware(inner, timeout=10)
            await mw(_make_scope(), None, _collect)

        _run(go())
        bodies = [m["body"] for m in messages if m["type"] == "http.response.body"]
        self.assertEqual(bodies, [b"hello"])


class TestRequestTimeoutMiddlewareTimeout(unittest.TestCase):
    """Slow requests are cancelled and receive a 408 response."""

    def _slow_inner(self, delay: float = 5.0):
        async def inner(scope, receive, send):
            await asyncio.sleep(delay)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"too slow"})
        return inner

    def test_408_returned_on_timeout(self):
        messages = []

        async def _collect(msg):
            messages.append(msg)

        async def go():
            mw = RequestTimeoutMiddleware(self._slow_inner(), timeout=0.05)
            await mw(_make_scope(), None, _collect)

        _run(go())
        statuses = [m.get("status") for m in messages if m["type"] == "http.response.start"]
        self.assertEqual(statuses, [408])

    def test_408_body_is_json(self):
        messages = []

        async def _collect(msg):
            messages.append(msg)

        async def go():
            mw = RequestTimeoutMiddleware(self._slow_inner(), timeout=0.05)
            await mw(_make_scope(), None, _collect)

        _run(go())
        bodies = [m.get("body", b"") for m in messages if m["type"] == "http.response.body"]
        self.assertTrue(any(b"detail" in b for b in bodies))

    def test_no_double_response_after_headers_sent(self):
        """If headers were already sent, no second 408 is attempted."""
        messages = []

        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await asyncio.sleep(5)  # slow after headers
            await send({"type": "http.response.body", "body": b"late"})

        async def _collect(msg):
            messages.append(msg)

        async def go():
            mw = RequestTimeoutMiddleware(inner, timeout=0.05)
            await mw(_make_scope(), None, _collect)

        _run(go())
        # Only one http.response.start should be present (the 200, not a 408)
        starts = [m for m in messages if m["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["status"], 200)

    def test_timeout_logs_warning(self):
        async def _noop(m): pass

        async def go():
            mw = RequestTimeoutMiddleware(self._slow_inner(), timeout=0.05)
            await mw(_make_scope("/slow"), None, _noop)

        with self.assertLogs("app.server_config", level=logging.WARNING) as cm:
            _run(go())
        self.assertTrue(any("timeout" in line.lower() for line in cm.output))

    def test_timeout_honours_configured_seconds(self):
        """The timeout value passed to the constructor is respected."""
        start = time.perf_counter()

        async def _noop(m): pass

        async def go():
            mw = RequestTimeoutMiddleware(self._slow_inner(delay=5), timeout=0.1)
            await mw(_make_scope(), None, _noop)

        _run(go())
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0, "Middleware should have fired at ~0.1s, not waited 5s")


if __name__ == "__main__":
    unittest.main()
