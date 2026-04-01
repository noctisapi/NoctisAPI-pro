"""InteractionContextBuilder — builds InteractionContext from request + response data.

PURPOSE:
  Provides a clean, injectable way to create InteractionContext objects that
  enrich the extra_json stored in the events table.

  This module is a BRIDGE: it translates what the middleware already knows
  (request method/path, response status, latency) plus what the new domain
  provides (EffectiveEndpoint) into a structured InteractionContext.

HOW IT FITS IN THE EXISTING FLOW:
  Inside the `finally` block of log_all_requests (honeypot_public.py),
  after the response is sent and before _insert_event() assembles extra_json:

    # --- ADDITIVE: new semantic enrichment ---
    effective_ep = resolve_effective_endpoint(request.method, request.url.path)
    if effective_ep is not None:
        ctx = build_interaction_context(
            effective_endpoint=effective_ep,
            status_code=status_code,
            response_bytes=response_bytes,
            latency_ms=latency_ms,
        )
        extra_json["interaction"] = ctx.to_extra_json_fragment()
    # --- END ADDITIVE ---
    # existing _insert_event() call follows, unchanged

  Nothing in the existing pipeline is changed. The "interaction" key is
  simply added to extra_json (or omitted if no catalog entry matches).

NEVER RAISES:
  All public functions catch exceptions and return None / empty dict on failure.
  The events pipeline must not be disrupted by enrichment failures.

FUTURE USE:
  - actors/actions: derive scoring hint from operation_type + sensitivity_level
  - session replay: reconstruct semantic context from stored extra_json
  - cases: tag evidence with operation_type / resource_type
  - campaigns: feature extraction (endpoint_id, template_id, triggered_flaws)

PUBLIC API:
  build_interaction_context(*)                → Optional[InteractionContext]
  safe_extra_json_fragment(*)                 → dict  (never raises, empty on failure)
  InteractionContextBuilder class             (injectable, for testing)
"""
from __future__ import annotations

import logging
from typing import Optional

from app.runtime.context import InteractionContext, InteractionOutcome
from app.runtime.models import EffectiveEndpoint

logger = logging.getLogger(__name__)


# ── Flaw trigger detection ────────────────────────────────────────────────────

def _detect_triggered_flaws(
    effective_endpoint: EffectiveEndpoint,
    status_code: int,
    extra_hints: Optional[dict] = None,
) -> tuple[str, ...]:
    """Determine which flaw profiles actually fired for this interaction.

    Heuristics (conservative, additive):
      - If the endpoint has a flaw configured, it is considered "triggered"
        unless the response indicates a hard error (500+) or the endpoint
        was not reached.
      - extra_hints can carry explicit trigger flags from route handlers.

    This is intentionally conservative: future versions can be more precise
    once ResponseFactory has full control over flaw execution.
    """
    if effective_endpoint.flaw is None:
        return ()

    # Explicit override from route handler (future use)
    if extra_hints:
        explicit = extra_hints.get("triggered_flaw_ids")
        if isinstance(explicit, (list, tuple)):
            return tuple(str(x) for x in explicit)

    # Default: if endpoint has flaw and response is not a server error,
    # assume flaw was active (conservative — better than missing it)
    if status_code < 500:
        return (effective_endpoint.flaw.profile_id,)

    return ()


# ── Builder class ─────────────────────────────────────────────────────────────

class InteractionContextBuilder:
    """Builds InteractionContext from middleware-available data.

    Stateless: all methods are pure functions of their inputs.
    Class form is provided for injection / subclassing in tests.
    """

    def build(
        self,
        *,
        effective_endpoint: EffectiveEndpoint,
        status_code: int,
        response_bytes: int = 0,
        latency_ms: int = 0,
        extra_hints: Optional[dict] = None,
    ) -> InteractionContext:
        """Build an InteractionContext. May raise on invalid inputs.

        Use build_interaction_context() for the safe (never-raises) version.

        Parameters:
          effective_endpoint  The EffectiveEndpoint resolved for this request.
          status_code         HTTP status code of the response (100–599).
          response_bytes      Size of the response body in bytes.
          latency_ms          Total request latency in milliseconds.
          extra_hints         Optional dict with overrides:
                               - "triggered_flaw_ids": list[str] (explicit flaw trigger)
                               - "error": str (error message if applicable)
        """
        triggered = _detect_triggered_flaws(
            effective_endpoint, status_code, extra_hints
        )
        error_msg = (extra_hints or {}).get("error")

        outcome = InteractionOutcome(
            status_code=status_code,
            response_bytes=response_bytes,
            latency_ms=latency_ms,
            flaw_triggered=len(triggered) > 0,
            error=error_msg,
        )

        return InteractionContext.from_effective_endpoint(
            endpoint_id=effective_endpoint.endpoint_id,
            operation_type=effective_endpoint.operation_type,
            surface_type=effective_endpoint.surface_type,
            resource_type=effective_endpoint.resource_type,
            sensitivity_level=effective_endpoint.sensitivity_level,
            template_id=effective_endpoint.template_id,
            extension_ids=effective_endpoint.extension_ids,
            triggered_flaws=triggered,
            outcome=outcome,
        )


# ── Module-level singleton builder ────────────────────────────────────────────

_builder = InteractionContextBuilder()


def build_interaction_context(
    *,
    effective_endpoint: EffectiveEndpoint,
    status_code: int,
    response_bytes: int = 0,
    latency_ms: int = 0,
    extra_hints: Optional[dict] = None,
) -> Optional[InteractionContext]:
    """Build an InteractionContext. Returns None on any error (never raises).

    This is the primary entry point for middleware use.

    Example usage in log_all_requests middleware (additive, non-destructive):

        effective_ep = resolve_effective_endpoint(request.method, request.url.path)
        if effective_ep is not None:
            ctx = build_interaction_context(
                effective_endpoint=effective_ep,
                status_code=status_code,
                response_bytes=len(body),
                latency_ms=int(elapsed * 1000),
            )
            if ctx is not None:
                extra_json["interaction"] = ctx.to_extra_json_fragment()
    """
    try:
        return _builder.build(
            effective_endpoint=effective_endpoint,
            status_code=status_code,
            response_bytes=response_bytes,
            latency_ms=latency_ms,
            extra_hints=extra_hints,
        )
    except Exception as exc:
        logger.debug(
            "build_interaction_context failed for endpoint_id=%r: %s",
            getattr(effective_endpoint, "endpoint_id", "?"),
            exc,
        )
        return None


def safe_extra_json_fragment(
    *,
    effective_endpoint: Optional[EffectiveEndpoint],
    status_code: int,
    response_bytes: int = 0,
    latency_ms: int = 0,
    extra_hints: Optional[dict] = None,
) -> dict:
    """Build the extra_json fragment. Returns empty dict if anything fails.

    This is the safest entry point for middleware: always returns a dict
    (possibly empty), never raises, never disrupts the events pipeline.

    Usage:
        extra_json["interaction"] = safe_extra_json_fragment(
            effective_endpoint=resolve_effective_endpoint(method, path),
            status_code=status_code,
            response_bytes=len(body),
            latency_ms=latency_ms,
        )
    """
    if effective_endpoint is None:
        return {}
    ctx = build_interaction_context(
        effective_endpoint=effective_endpoint,
        status_code=status_code,
        response_bytes=response_bytes,
        latency_ms=latency_ms,
        extra_hints=extra_hints,
    )
    if ctx is None:
        return {}
    try:
        return ctx.to_extra_json_fragment()
    except Exception:
        return {}


# ── Interfaces for future ResponseFactory ─────────────────────────────────────
#
# Phase 2 (ResponseFactory) will add:
#
#   build_response(
#       *,
#       effective_endpoint: EffectiveEndpoint,
#       request_context: dict,          # method, path, actor_id, headers...
#   ) -> ResponseSpec
#
# ResponseSpec will carry:
#   - body (generated fake JSON)
#   - status_code (from flaw / fixed_status / operation_type default)
#   - headers (from profile + flaw)
#   - triggered_flaws (detected during generation)
#
# Then InteractionContextBuilder will receive ResponseSpec.triggered_flaws
# instead of the heuristic _detect_triggered_flaws() used here.
#
# The hook point in the middleware is already clear:
#
#   [EXISTING]   api_modular.resolve_request_policy() → policy dict
#   [EXISTING]   api_modular.mutate_json_payload()    → mutated body
#
#   [PHASE 2]    ResponseFactory.build(effective_ep, request) → ResponseSpec
#                replaces mutate_json_payload() for catalog-mapped endpoints
#                api_modular path remains as fallback for unmapped endpoints
