"""Tests for app.no_cache — NoCacheMiddleware.

Covers:
 - No-cache headers injected on normal responses
 - ETag and Last-Modified stripped from responses
 - Existing Cache-Control / Pragma / Expires overridden
 - 304 responses converted to 200 with empty body
 - /static/ paths skipped when HP_NO_CACHE_SKIP_STATIC=true (default)
 - /static/ paths processed when HP_NO_CACHE_SKIP_STATIC=false
 - Middleware disabled via HP_NO_CACHE_ENABLED=false
 - Non-HTTP scopes pass through unchanged
 - Headers added to swagger/redoc/openapi.json paths
"""

from __future__ import annotations

import asyncio
import os
import unittest
from typing import Any


# ---------------------------------------------------------------------------
# ASGI helpers
# ---------------------------------------------------------------------------


def _make_scope(path: str = "/api/test", method: str = "GET") -> dict:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [],
    }


def _make_websocket_scope() -> dict:
    return {"type": "websocket", "path": "/ws"}


class _ResponseCapture:
    """Minimal ASGI send() mock that records messages sent."""

    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def __call__(self, message: dict) -> None:
        self.messages.append(message)

    @property
    def start(self) -> dict | None:
        for m in self.messages:
            if m.get("type") == "http.response.start":
                return m
        return None

    @property
    def status(self) -> int | None:
        if self.start:
            return self.start.get("status")
        return None

    @property
    def headers(self) -> dict[str, str]:
        if not self.start:
            return {}
        return {
            k.decode().lower(): v.decode()
            for k, v in (self.start.get("headers") or [])
        }

    @property
    def body(self) -> bytes:
        for m in self.messages:
            if m.get("type") == "http.response.body":
                return m.get("body", b"")
        return b""


def _make_app(
    status: int = 200,
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"ok",
) -> Any:
    """Return a minimal ASGI app that sends a fixed response."""
    _headers = headers or []

    async def _inner(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": status, "headers": _headers})
        await send({"type": "http.response.body", "body": body})

    return _inner


def _run(coro) -> Any:
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Helper to instantiate middleware with env overrides
# ---------------------------------------------------------------------------


class _EnvOverride:
    _VARS = ("HP_NO_CACHE_ENABLED", "HP_NO_CACHE_SKIP_STATIC")

    def __init__(self, **kwargs):
        self._overrides = kwargs
        self._saved: dict = {}

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


def _build_middleware(**env):
    """Build a NoCacheMiddleware instance with given env vars."""
    # Import inside the env override so _is_enabled() / _skip_static() read
    # the patched env at construction time.
    with _EnvOverride(**env):
        # Re-import to pick up fresh env reads at __init__ time.
        import importlib
        import app.no_cache as _mod
        importlib.reload(_mod)
        return _mod.NoCacheMiddleware


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNoCacheHeadersInjected(unittest.TestCase):
    """No-cache headers are added to ordinary responses."""

    def _run(self, path: str = "/api/v1/users") -> _ResponseCapture:
        import importlib
        import app.no_cache as _mod
        importlib.reload(_mod)
        inner = _make_app(status=200)
        mw = _mod.NoCacheMiddleware(inner)
        capture = _ResponseCapture()
        _run(mw(_make_scope(path=path), None, capture))
        return capture

    def test_cache_control_present(self):
        h = self._run().headers
        self.assertIn("cache-control", h)
        self.assertIn("no-store", h["cache-control"])

    def test_cache_control_value(self):
        h = self._run().headers
        self.assertEqual(
            h["cache-control"],
            "no-store, no-cache, must-revalidate, max-age=0, private",
        )

    def test_pragma_present(self):
        h = self._run().headers
        self.assertEqual(h.get("pragma"), "no-cache")

    def test_expires_present(self):
        h = self._run().headers
        self.assertEqual(h.get("expires"), "0")

    def test_status_unchanged(self):
        self.assertEqual(self._run().status, 200)

    def test_body_unchanged(self):
        self.assertEqual(self._run().body, b"ok")


class TestETagStripped(unittest.TestCase):
    """ETag and Last-Modified headers are stripped from responses."""

    def _run(self, extra_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
        import importlib
        import app.no_cache as _mod
        importlib.reload(_mod)
        inner = _make_app(status=200, headers=extra_headers)
        mw = _mod.NoCacheMiddleware(inner)
        capture = _ResponseCapture()
        _run(mw(_make_scope(), None, capture))
        return capture.headers

    def test_etag_stripped(self):
        h = self._run([(b"etag", b'"abc123"')])
        self.assertNotIn("etag", h)

    def test_last_modified_stripped(self):
        h = self._run([(b"last-modified", b"Wed, 01 Jan 2025 00:00:00 GMT")])
        self.assertNotIn("last-modified", h)

    def test_etag_case_insensitive(self):
        h = self._run([(b"ETag", b'"xyz"')])
        self.assertNotIn("etag", h)

    def test_other_headers_preserved(self):
        h = self._run([(b"x-custom", b"value"), (b"content-type", b"application/json")])
        self.assertEqual(h.get("x-custom"), "value")
        self.assertEqual(h.get("content-type"), "application/json")


class TestExistingCacheControlOverridden(unittest.TestCase):
    """Route-level Cache-Control / Pragma / Expires are overridden by middleware."""

    def _run(self, headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
        import importlib
        import app.no_cache as _mod
        importlib.reload(_mod)
        inner = _make_app(status=200, headers=headers)
        mw = _mod.NoCacheMiddleware(inner)
        capture = _ResponseCapture()
        _run(mw(_make_scope(), None, capture))
        return capture.headers

    def test_route_cache_control_overridden(self):
        h = self._run([(b"cache-control", b"max-age=3600, public")])
        self.assertIn("no-store", h["cache-control"])
        self.assertNotIn("max-age=3600", h["cache-control"])

    def test_route_pragma_overridden(self):
        h = self._run([(b"pragma", b"custom")])
        self.assertEqual(h["pragma"], "no-cache")

    def test_route_expires_overridden(self):
        h = self._run([(b"expires", b"Thu, 01 Jan 2099 00:00:00 GMT")])
        self.assertEqual(h["expires"], "0")


class Test304Conversion(unittest.TestCase):
    """304 responses are converted to 200 with an empty body."""

    def _run_304(self) -> _ResponseCapture:
        import importlib
        import app.no_cache as _mod
        importlib.reload(_mod)
        inner = _make_app(status=304, headers=[(b"etag", b'"stale"')], body=b"")
        mw = _mod.NoCacheMiddleware(inner)
        capture = _ResponseCapture()
        _run(mw(_make_scope(), None, capture))
        return capture

    def test_304_becomes_200(self):
        self.assertEqual(self._run_304().status, 200)

    def test_304_body_empty(self):
        self.assertEqual(self._run_304().body, b"")

    def test_304_no_cache_headers_present(self):
        h = self._run_304().headers
        self.assertIn("no-store", h.get("cache-control", ""))

    def test_304_etag_stripped(self):
        self.assertNotIn("etag", self._run_304().headers)


class TestStaticPathsSkipped(unittest.TestCase):
    """/static/* paths are skipped when HP_NO_CACHE_SKIP_STATIC=true (default)."""

    def _run(self, path: str, skip_static: str = "true") -> _ResponseCapture:
        with _EnvOverride(HP_NO_CACHE_SKIP_STATIC=skip_static):
            import importlib
            import app.no_cache as _mod
            importlib.reload(_mod)
            inner = _make_app(status=200)
            mw = _mod.NoCacheMiddleware(inner)
            capture = _ResponseCapture()
            _run(mw(_make_scope(path=path), None, capture))
            return capture

    def test_static_path_no_cache_header_absent(self):
        h = self._run("/static/table_utils.js").headers
        self.assertNotIn("cache-control", h)

    def test_non_static_path_has_header(self):
        h = self._run("/api/v1/users").headers
        self.assertIn("cache-control", h)

    def test_static_skipped_false_adds_headers(self):
        h = self._run("/static/table_utils.js", skip_static="false").headers
        self.assertIn("cache-control", h)


class TestMiddlewareDisabled(unittest.TestCase):
    """HP_NO_CACHE_ENABLED=false makes middleware a transparent no-op."""

    def _run_disabled(self, path: str = "/api/v1/users") -> _ResponseCapture:
        with _EnvOverride(HP_NO_CACHE_ENABLED="false"):
            import importlib
            import app.no_cache as _mod
            importlib.reload(_mod)
            inner = _make_app(
                status=200,
                headers=[(b"etag", b'"kept"'), (b"cache-control", b"max-age=3600")],
            )
            mw = _mod.NoCacheMiddleware(inner)
            capture = _ResponseCapture()
            _run(mw(_make_scope(path=path), None, capture))
            return capture

    def test_disabled_no_cache_header_absent(self):
        # Middleware does not inject no-store when disabled; the inner app's own
        # cache-control header (max-age=3600) may still be present.
        cc = self._run_disabled().headers.get("cache-control", "")
        self.assertNotIn("no-store", cc)

    def test_disabled_etag_preserved(self):
        self.assertIn("etag", self._run_disabled().headers)

    def test_disabled_status_unchanged(self):
        self.assertEqual(self._run_disabled().status, 200)

    def test_disabled_flags(self):
        for val in ("false", "0", "no"):
            with _EnvOverride(HP_NO_CACHE_ENABLED=val):
                import importlib
                import app.no_cache as _mod
                importlib.reload(_mod)
                self.assertFalse(_mod._is_enabled(), f"expected disabled for HP_NO_CACHE_ENABLED={val!r}")

    def test_enabled_flags(self):
        for val in ("true", "1", "yes", "TRUE"):
            with _EnvOverride(HP_NO_CACHE_ENABLED=val):
                import importlib
                import app.no_cache as _mod
                importlib.reload(_mod)
                self.assertTrue(_mod._is_enabled(), f"expected enabled for HP_NO_CACHE_ENABLED={val!r}")


class TestNonHttpScope(unittest.TestCase):
    """Non-HTTP scopes (websocket, lifespan) pass through unchanged."""

    def test_websocket_passthrough(self):
        import importlib
        import app.no_cache as _mod
        importlib.reload(_mod)

        called = []

        async def inner(scope, receive, send):
            called.append(scope["type"])

        mw = _mod.NoCacheMiddleware(inner)
        _run(mw(_make_websocket_scope(), None, None))
        self.assertEqual(called, ["websocket"])


class TestSwaggerPaths(unittest.TestCase):
    """Anti-cache headers applied to swagger / redoc / openapi.json."""

    def _run(self, path: str) -> dict[str, str]:
        import importlib
        import app.no_cache as _mod
        importlib.reload(_mod)
        inner = _make_app(status=200)
        mw = _mod.NoCacheMiddleware(inner)
        capture = _ResponseCapture()
        _run(mw(_make_scope(path=path), None, capture))
        return capture.headers

    def test_docs_path(self):
        self.assertIn("no-store", self._run("/docs").get("cache-control", ""))

    def test_redoc_path(self):
        self.assertIn("no-store", self._run("/redoc").get("cache-control", ""))

    def test_openapi_json_path(self):
        self.assertIn("no-store", self._run("/openapi.json").get("cache-control", ""))


if __name__ == "__main__":
    unittest.main()
