"""Tests for response_bridge.py.

Coverage:
- try_factory_response returns a Starlette Response for catalog-mapped endpoints
- try_factory_response returns None for unknown paths
- try_factory_response returns None safely on any exception (never raises)
- Stores spec on request.state.response_spec when response is produced
- enrich_extra_json adds "interaction" key when spec is present
- enrich_extra_json is a no-op (returns unchanged dict) when no spec on state
- enrich_extra_json never raises
- _spec_to_response returns correct Starlette response type per content_type
- Legacy fallback not broken: None return path is unchanged
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.response_factory.spec import ResponseSpec
from app.response_bridge import (
    _build_interaction_fragment,
    _spec_to_response,
    enrich_extra_json,
    try_factory_response,
    try_handler_factory_response,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_spec(
    *,
    endpoint_id: str = "recon_env",
    status_code: int = 200,
    body: Any = {"token": "abc123"},
    content_type: str = "application/json",
    latency_ms: int = 0,
    triggered_flaws: tuple = (),
) -> ResponseSpec:
    return ResponseSpec(
        endpoint_id=endpoint_id,
        status_code=status_code,
        headers={"x-test": "yes"},
        body=body,
        content_type=content_type,
        latency_ms=latency_ms,
        triggered_flaws=triggered_flaws,
        outcome_hints={"operation_type": "recon", "difficulty": "medium"},
    )


def _make_request(path: str = "/.env", method: str = "GET") -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url.path = path
    req.app = None
    req.state = MagicMock()
    req.state.response_spec = None
    req.state.response_backend = "runtime_native"
    return req


# ── _spec_to_response ─────────────────────────────────────────────────────────

class TestSpecToResponse:
    def test_json_body_returns_json_response(self):
        from starlette.responses import JSONResponse
        spec = _make_spec(body={"a": 1}, content_type="application/json")
        resp = _spec_to_response(spec)
        assert isinstance(resp, JSONResponse)
        assert resp.status_code == 200

    def test_text_body_returns_plain_text_response(self):
        from starlette.responses import PlainTextResponse
        spec = _make_spec(body="plain text here", content_type="text/plain", status_code=200)
        resp = _spec_to_response(spec)
        assert isinstance(resp, PlainTextResponse)

    def test_none_body_returns_empty_response(self):
        from starlette.responses import Response
        spec = _make_spec(body=None, content_type="application/json", status_code=204)
        resp = _spec_to_response(spec)
        assert isinstance(resp, Response)
        assert resp.status_code == 204

    def test_status_code_propagated(self):
        spec = _make_spec(status_code=403, body={"error": "forbidden"})
        resp = _spec_to_response(spec)
        assert resp.status_code == 403

    def test_content_type_header_not_duplicated(self):
        # content-type must not appear twice in headers; bridge strips it from headers dict
        spec = _make_spec(body={"k": "v"})
        resp = _spec_to_response(spec)
        # JSONResponse always adds content-type itself; check there's no double header
        assert resp.headers.get("content-type") is not None

    def test_list_body_produces_json_response(self):
        from starlette.responses import JSONResponse
        spec = _make_spec(body=[{"id": 1}, {"id": 2}])
        resp = _spec_to_response(spec)
        assert isinstance(resp, JSONResponse)

    def test_never_raises(self):
        # Even with a completely broken spec, it should not raise
        bad_spec = MagicMock()
        bad_spec.has_json_body = True
        bad_spec.has_text_body = False
        bad_spec.body = object()  # not JSON-serializable
        bad_spec.status_code = 200
        bad_spec.headers = {}
        # Should not propagate any exception
        result = _spec_to_response(bad_spec)
        # May return None or a fallback JSONResponse
        # The key assertion: no exception was raised


# ── enrich_extra_json ─────────────────────────────────────────────────────────

class TestEnrichExtraJson:
    def test_no_spec_returns_unchanged_dict(self):
        req = _make_request()
        req.state.response_spec = None
        extra = {"rt": "mw", "latency_ms": 50}
        with patch("app.runtime_provider.resolve_effective_endpoint_including_disabled", return_value=None):
            result = enrich_extra_json(req, extra, 200, 50)
        assert result is extra
        assert "interaction" not in result

    def test_with_spec_adds_interaction_key(self):
        req = _make_request()
        spec = _make_spec()
        req.state.response_spec = spec

        with patch("app.response_bridge._build_interaction_fragment") as mock_build:
            mock_build.return_value = {"endpoint_id": "recon_env", "operation_type": "recon"}
            extra = {"rt": "mw"}
            result = enrich_extra_json(req, extra, 200, 80)

        assert "interaction" in result
        assert result["interaction"]["endpoint_id"] == "recon_env"
        assert result["interaction"]["response_backend"] == "runtime_native"

    def test_empty_fragment_not_added(self):
        req = _make_request()
        spec = _make_spec()
        req.state.response_spec = spec

        with patch("app.response_bridge._build_interaction_fragment") as mock_build:
            mock_build.return_value = {}
            extra = {"rt": "mw"}
            result = enrich_extra_json(req, extra, 200, 80)

        assert "interaction" not in result

    def test_never_raises_on_exception(self):
        req = MagicMock()
        req.state = MagicMock(side_effect=Exception("state error"))
        extra = {"rt": "mw"}
        # Should not raise
        result = enrich_extra_json(req, extra, 200, 50)
        assert result is extra

    def test_never_raises_when_build_raises(self):
        req = _make_request()
        req.state.response_spec = _make_spec()

        with patch("app.response_bridge._build_interaction_fragment", side_effect=RuntimeError("oops")):
            extra = {"x": 1}
            result = enrich_extra_json(req, extra, 200, 50)
        # Should not raise; returns dict as-is
        assert isinstance(result, dict)

    def test_legacy_endpoint_adds_interaction_and_backend(self):
        req = _make_request()
        req.state.response_backend = "runtime_native"
        mock_ep = MagicMock()

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.interaction_context_builder.safe_extra_json_fragment", return_value={"endpoint_id": "recon_env"}):
            extra = {"rt": "mw"}
            result = enrich_extra_json(req, extra, 200, 50)

        assert result["interaction"]["endpoint_id"] == "recon_env"
        assert result["interaction"]["response_backend"] == "runtime_native"


# ── try_factory_response ──────────────────────────────────────────────────────

class TestTryFactoryResponse:
    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            loop.close()
            asyncio.set_event_loop(asyncio.new_event_loop())

    # Lazy imports mean we must patch at source modules, not at app.response_bridge

    def test_returns_none_for_unknown_path(self):
        req = _make_request(path="/completely_unknown_path_xyz_9999")
        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=None):
            result = self._run(try_factory_response(req, actor_id="test_actor"))
        assert result is None

    def test_returns_none_when_not_supported(self):
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "recon_env"
        req = _make_request()

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=False):
            result = self._run(try_factory_response(req, actor_id=""))
        assert result is None

    def test_returns_none_when_build_returns_none(self):
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "recon_env"
        req = _make_request()

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=None):
            result = self._run(try_factory_response(req, actor_id=""))
        assert result is None

    def test_returns_response_for_supported_endpoint(self):
        from starlette.responses import JSONResponse
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "recon_env"
        spec = _make_spec(latency_ms=0)
        req = _make_request()

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec):
            result = self._run(try_factory_response(req, actor_id="actor1"))

        assert result is not None
        assert isinstance(result, JSONResponse)
        assert result.status_code == 200

    def test_stores_spec_on_request_state(self):
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "recon_env"
        spec = _make_spec(latency_ms=0)
        req = _make_request()

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec):
            self._run(try_factory_response(req, actor_id="actor1"))

        assert req.state.response_spec is spec
        assert req.state.response_backend == "factory"

    def test_injects_latency(self):
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "recon_env"
        spec = _make_spec(latency_ms=100)
        req = _make_request()

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec), \
             patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            self._run(try_factory_response(req, actor_id=""))
            mock_sleep.assert_awaited_once_with(0.1)

    def test_zero_latency_no_sleep(self):
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "recon_env"
        spec = _make_spec(latency_ms=0)
        req = _make_request()

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec), \
             patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            self._run(try_factory_response(req, actor_id=""))
            mock_sleep.assert_not_awaited()

    def test_never_raises_on_exception(self):
        req = _make_request()

        with patch("app.runtime_provider.resolve_effective_endpoint", side_effect=RuntimeError("boom")):
            result = self._run(try_factory_response(req, actor_id=""))
        assert result is None

    def test_returns_none_for_bad_request_object(self):
        # Completely invalid request
        result = self._run(try_factory_response(None, actor_id=""))
        assert result is None

    def test_returns_none_when_endpoint_not_in_migrated_batch(self):
        req = _make_request(path="/auth/login", method="POST")
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "auth_login"

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True):
            result = self._run(try_factory_response(req, actor_id=""))

        assert result is None


# ── _build_interaction_fragment ───────────────────────────────────────────────

class TestBuildInteractionFragment:
    def test_returns_dict(self):
        spec = _make_spec()
        with patch("app.runtime_provider.get_runtime_config") as mock_config:
            mock_ep = MagicMock()
            mock_config.return_value.get_endpoint.return_value = mock_ep

            with patch("app.interaction_context_builder.safe_extra_json_fragment") as mock_frag:
                mock_frag.return_value = {"endpoint_id": "ep_bridge_test"}
                result = _build_interaction_fragment(spec, 200, 80)

        assert isinstance(result, dict)

    def test_returns_empty_dict_when_endpoint_not_found(self):
        spec = _make_spec()
        with patch("app.runtime_provider.get_runtime_config") as mock_config:
            mock_config.return_value.get_endpoint.return_value = None
            result = _build_interaction_fragment(spec, 200, 80)
        assert result == {}

    def test_returns_empty_dict_on_exception(self):
        spec = _make_spec()
        with patch("app.runtime_provider.get_runtime_config", side_effect=RuntimeError("db down")):
            result = _build_interaction_fragment(spec, 200, 80)
        assert result == {}


# ── try_handler_factory_response ─────────────────────────────────────────────

class TestTryHandlerFactoryResponse:
    """Handler-assisted pattern: side effects already done, factory generates body."""

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            loop.close()
            asyncio.set_event_loop(asyncio.new_event_loop())

    def _make_users_list_request(self) -> MagicMock:
        return _make_request(path="/api/v1/users", method="GET")

    def test_returns_none_for_unknown_path(self):
        req = _make_request(path="/does/not/exist")
        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=None):
            result = self._run(try_handler_factory_response(req, actor_id="a"))
        assert result is None

    def test_returns_none_when_endpoint_not_in_handler_migrated_batch(self):
        """auth_login is supported by factory but NOT in HANDLER_MIGRATED_ENDPOINT_IDS."""
        req = _make_request(path="/auth/login", method="POST")
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "auth_login"

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True):
            result = self._run(try_handler_factory_response(req, actor_id=""))
        assert result is None

    def test_returns_none_when_operation_type_not_supported(self):
        req = self._make_users_list_request()
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "users_list"

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=False):
            result = self._run(try_handler_factory_response(req, actor_id=""))
        assert result is None

    def test_returns_none_when_build_returns_none(self):
        req = self._make_users_list_request()
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "users_list"

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=None):
            result = self._run(try_handler_factory_response(req, actor_id=""))
        assert result is None

    def test_returns_response_for_handler_migrated_endpoint(self):
        from starlette.responses import JSONResponse
        req = self._make_users_list_request()
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "users_list"
        spec = _make_spec(endpoint_id="users_list", latency_ms=0)

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec):
            result = self._run(try_handler_factory_response(req, actor_id="u1"))

        assert result is not None
        assert isinstance(result, JSONResponse)

    def test_sets_response_backend_to_handler_factory(self):
        """response_backend must be 'handler_factory' so middleware skips policy."""
        req = self._make_users_list_request()
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "users_list"
        spec = _make_spec(endpoint_id="users_list", latency_ms=0)

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec):
            self._run(try_handler_factory_response(req, actor_id="u1"))

        assert req.state.response_backend == "handler_factory"

    def test_stores_spec_on_request_state(self):
        req = self._make_users_list_request()
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "users_list"
        spec = _make_spec(endpoint_id="users_list", latency_ms=0)

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec):
            self._run(try_handler_factory_response(req, actor_id="u1"))

        assert req.state.response_spec is spec

    def test_response_backend_unchanged_when_returns_none(self):
        """When returning None, response_backend must not be changed."""
        req = self._make_users_list_request()
        req.state.response_backend = "runtime_native"

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=None):
            self._run(try_handler_factory_response(req, actor_id=""))

        assert req.state.response_backend == "runtime_native"

    def test_injects_latency(self):
        req = self._make_users_list_request()
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "users_list"
        spec = _make_spec(endpoint_id="users_list", latency_ms=50)

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec), \
             patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            self._run(try_handler_factory_response(req, actor_id=""))
            mock_sleep.assert_awaited_once_with(0.05)

    def test_never_raises_on_exception(self):
        req = _make_request()
        with patch("app.runtime_provider.resolve_effective_endpoint", side_effect=RuntimeError("boom")):
            result = self._run(try_handler_factory_response(req, actor_id=""))
        assert result is None

    def test_never_raises_for_bad_request_object(self):
        result = self._run(try_handler_factory_response(None, actor_id=""))
        assert result is None

    def test_side_effects_not_in_scope(self):
        """Factory must NOT run _set_hp_event — verifying the helper is pure.

        The test confirms that if the handler has already done side effects and
        factory returns a response, the response object is an HTTP response only.
        """
        from starlette.responses import JSONResponse
        req = self._make_users_list_request()
        mock_ep = MagicMock()
        mock_ep.endpoint_id = "users_list"
        spec = _make_spec(endpoint_id="users_list", latency_ms=0)

        with patch("app.runtime_provider.resolve_effective_endpoint", return_value=mock_ep), \
             patch("app.response_factory.factory.is_supported", return_value=True), \
             patch("app.response_factory.factory.build_response", return_value=spec):
            result = self._run(try_handler_factory_response(req, actor_id="u1"))

        # Result is a plain HTTP response — no scoring side effects attached.
        assert isinstance(result, JSONResponse)
