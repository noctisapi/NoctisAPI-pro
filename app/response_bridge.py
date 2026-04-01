"""Progressive integration point between ResponseFactory and legacy handlers."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _request_has_registered_route(request: Any) -> bool:
    """True when the incoming request resolves to a real ASGI route.

    Unit tests often use lightweight request doubles with no app/routes table.
    In those cases, stay permissive so the bridge can be tested in isolation.
    """
    try:
        from starlette.routing import Match

        app = getattr(request, "app", None)
        routes = getattr(app, "routes", None)
        if not routes:
            return True

        scope = {
            "type": "http",
            "method": str(getattr(request, "method", "")).upper(),
            "path": str(getattr(getattr(request, "url", None), "path", "")),
        }
        for route in routes:
            match, _ = route.matches(scope)
            if match == Match.FULL:
                return True
        return False
    except Exception:
        return True


def _response_backend(request: Any) -> str:
    try:
        return str(getattr(getattr(request, "state", None), "response_backend", "legacy") or "legacy")
    except Exception:
        return "legacy"


async def try_factory_response(
    request: Any,
    *,
    actor_id: str = "",
) -> Optional[Any]:
    """Try to serve the request via ResponseFactory.

    Returns a Starlette Response when:
    - the request resolves to a catalog endpoint
    - that endpoint is supported by the factory
    - that endpoint_id is in the explicit migrated batch
    - the request matches a registered route

    Returns None for every other case so the middleware falls back to legacy.
    Never raises.
    """
    try:
        from app.runtime_provider import resolve_effective_endpoint
        from app.response_factory.factory import build_response, is_supported
        from app.response_factory.migration import is_migrated_endpoint

        method = request.method
        path = request.url.path

        effective_ep = resolve_effective_endpoint(method, path)
        if effective_ep is None:
            return None
        if not is_supported(effective_ep):
            return None
        if not is_migrated_endpoint(effective_ep.endpoint_id):
            return None
        if not _request_has_registered_route(request):
            return None

        spec = build_response(effective_ep, salt=actor_id)
        if spec is None:
            return None

        try:
            request.state.response_spec = spec
            request.state.response_backend = "factory"
        except Exception:
            pass

        if spec.latency_ms > 0:
            await asyncio.sleep(spec.latency_ms / 1000.0)

        return _spec_to_response(spec)

    except Exception as exc:
        logger.debug(
            "try_factory_response failed for %s %s: %s",
            getattr(request, "method", "?"),
            getattr(getattr(request, "url", None), "path", "?"),
            exc,
        )
        return None


def enrich_extra_json(
    request: Any,
    extra_json: dict[str, Any],
    status_code: int,
    latency_ms: int,
) -> dict[str, Any]:
    """Enrich extra_json with semantic interaction metadata.

    Factory path uses ResponseSpec.triggered_flaws.
    Legacy path still gets a stable semantic fragment when the request resolves
    to a catalog endpoint.
    """
    try:
        spec: Optional[Any] = getattr(getattr(request, "state", None), "response_spec", None)
        if spec is not None:
            fragment = _build_interaction_fragment(spec, status_code, latency_ms)
        else:
            fragment = _build_legacy_interaction_fragment(request, status_code, latency_ms)

        if fragment:
            fragment["response_backend"] = _response_backend(request)
            extra_json["interaction"] = fragment
    except Exception as exc:
        logger.debug("enrich_extra_json failed: %s", exc)

    return extra_json


def _build_interaction_fragment(
    spec: Any,
    status_code: int,
    latency_ms: int,
) -> dict[str, Any]:
    """Build the interaction fragment from a ResponseSpec. Never raises."""
    try:
        from app.runtime_provider import get_runtime_config

        config = get_runtime_config()
        effective_ep = config.get_endpoint(spec.endpoint_id)
        if effective_ep is None:
            return {}

        return _build_interaction_fragment_from_endpoint(
            effective_endpoint=effective_ep,
            status_code=status_code,
            response_bytes=spec.response_bytes,
            latency_ms=latency_ms,
            extra_hints={
                "triggered_flaw_ids": list(spec.triggered_flaws),
                **(spec.outcome_hints or {}),
            },
        )
    except Exception:
        return {}


def _build_legacy_interaction_fragment(
    request: Any,
    status_code: int,
    latency_ms: int,
) -> dict[str, Any]:
    """Build the interaction fragment from request routing data. Never raises."""
    try:
        from app.runtime_provider import resolve_effective_endpoint

        effective_ep = resolve_effective_endpoint(
            str(getattr(request, "method", "")),
            str(getattr(getattr(request, "url", None), "path", "")),
        )
        if effective_ep is None:
            return {}

        return _build_interaction_fragment_from_endpoint(
            effective_endpoint=effective_ep,
            status_code=status_code,
            response_bytes=0,
            latency_ms=latency_ms,
            extra_hints=None,
        )
    except Exception:
        return {}


def _build_interaction_fragment_from_endpoint(
    *,
    effective_endpoint: Any,
    status_code: int,
    response_bytes: int,
    latency_ms: int,
    extra_hints: Optional[dict[str, Any]],
) -> dict[str, Any]:
    try:
        from app.interaction_context_builder import safe_extra_json_fragment

        return safe_extra_json_fragment(
            effective_endpoint=effective_endpoint,
            status_code=status_code,
            response_bytes=response_bytes,
            latency_ms=latency_ms,
            extra_hints=extra_hints,
        )
    except Exception:
        return {}


def _spec_to_response(spec: Any) -> Any:
    """Convert a ResponseSpec to a Starlette Response. Never raises."""
    try:
        from starlette.responses import JSONResponse, PlainTextResponse, Response

        headers = {k: v for k, v in spec.headers.items() if k.lower() != "content-type"}

        if spec.has_json_body:
            return JSONResponse(
                status_code=spec.status_code,
                content=spec.body,
                headers=headers,
            )
        if spec.has_text_body:
            return PlainTextResponse(
                status_code=spec.status_code,
                content=str(spec.body),
                headers=headers,
            )
        if spec.body is None:
            return Response(status_code=spec.status_code, headers=headers)

        return JSONResponse(
            status_code=spec.status_code,
            content=spec.body,
            headers=headers,
        )
    except Exception as exc:
        logger.debug("_spec_to_response failed: %s", exc)
        try:
            from starlette.responses import JSONResponse

            return JSONResponse(status_code=200, content={"status": "ok"})
        except Exception:
            return None
