"""ResponseFactory — builds a ResponseSpec from an EffectiveEndpoint.

PUBLIC API:
  ResponseFactory.build(effective_endpoint, *, salt="") → ResponseSpec
  is_supported(effective_endpoint)                       → bool

ALGORITHM:
  1. Check is_supported() — returns None if not.
  2. Determine base status code: fixed_status > operation_type default.
  3. Generate payload via generators.generate_payload().
  4. Apply flaw behavior via flaw_applicator.apply_flaw() if flaw is set.
  5. Apply difficulty-based response adjustments (error_trap, richness).
  6. Merge profile headers + effective headers.
  7. Compute latency from profile range.
  8. Return ResponseSpec.

SUPPORTED:
  An endpoint is supported when its operation_type has a generator registered
  in generators.SUPPORTED_OPERATION_TYPES.
  This is deterministic and testable.

NO DB ACCESS. NO STARLETTE DEPENDENCY.
"""
from __future__ import annotations

import hashlib
import random
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.catalog.types import Difficulty, OperationType
from app.response_factory.flaw_applicator import apply_flaw
from app.response_factory.generators import (
    SUPPORTED_OPERATION_TYPES,
    default_content_type_for,
    default_status_for,
    generate_payload,
)
from app.response_factory.spec import ResponseSpec
from app.runtime.models import EffectiveEndpoint

_INT_TEMPLATE_RE = re.compile(r"^\{\{int:(\d+)-(\d+)\}\}$")


def is_supported(endpoint: EffectiveEndpoint) -> bool:
    """Return True when ResponseFactory can generate a response for this endpoint.

    Deterministic: depends only on operation_type.
    This is the gate check for progressive integration.
    """
    return endpoint.operation_type in SUPPORTED_OPERATION_TYPES


class ResponseFactory:
    """Generates ResponseSpec from an EffectiveEndpoint.

    Stateless: all state is derived from the endpoint definition and a
    seeded RNG (seeded from endpoint_id + date). Safe to call from async
    contexts (no I/O, no blocking).

    Usage:
        factory = ResponseFactory()
        spec = factory.build(effective_endpoint)
        if spec is None:
            # fall back to legacy handler
    """

    def build(
        self,
        effective_endpoint: EffectiveEndpoint,
        *,
        salt: str = "",
    ) -> Optional[ResponseSpec]:
        """Build a ResponseSpec for the given endpoint.

        Returns None if the endpoint is not supported (safe to call speculatively).

        Parameters:
          effective_endpoint  The fully resolved endpoint from EffectiveRuntimeConfig.
          salt                Optional per-request salt for response variation.
                              Pass actor_id or request_id to avoid identical responses
                              for identical requests within the same day.
        """
        if not is_supported(effective_endpoint):
            return None

        operation_type = effective_endpoint.operation_type
        resource_type = effective_endpoint.resource_type
        difficulty = effective_endpoint.response.difficulty
        endpoint_id = effective_endpoint.endpoint_id

        # 1. Generate base payload
        payload = generate_payload(
            operation_type=operation_type,
            resource_type=resource_type,
            difficulty=difficulty,
            endpoint_id=endpoint_id,
            salt=salt,
        )

        # 2. Determine status code: fixed_status > operation default
        status_code = (
            effective_endpoint.response.fixed_status
            if effective_endpoint.response.fixed_status is not None
            else default_status_for(operation_type)
        )

        # 3. Content type (flaw may override later)
        content_type = default_content_type_for(operation_type, endpoint_id)

        # 4. Apply flaw if present
        triggered_flaws: list[str] = []
        if effective_endpoint.flaw is not None:
            mutated, fired, ct_override = apply_flaw(
                payload,
                effective_endpoint.flaw,
                operation_type=operation_type,
                status_code=status_code,
                endpoint_id=endpoint_id,
                salt=salt,
            )
            if fired:
                payload = mutated
                triggered_flaws.append(effective_endpoint.flaw.profile_id)
                if ct_override:
                    content_type = ct_override

        # 5. Apply error_bias if difficulty profile says so
        if (
            effective_endpoint.response.fixed_status is None
            and effective_endpoint.response.error_format == "json"
            and self._should_error_bias(effective_endpoint, salt)
        ):
            status_code = self._pick_error_status(effective_endpoint, salt)
            payload = self._error_payload(effective_endpoint, status_code)

        # 6. Build headers: profile defaults + endpoint overrides
        headers = self._render_headers(
            effective_endpoint.response.headers,
            endpoint_id=endpoint_id,
            salt=salt,
        )
        # Ensure content-type matches what we're sending
        headers["content-type"] = content_type

        # 7. Compute latency
        latency_ms = self._sample_latency(effective_endpoint, salt)

        return ResponseSpec(
            endpoint_id=endpoint_id,
            status_code=status_code,
            headers=headers,
            body=payload,
            content_type=content_type,
            latency_ms=latency_ms,
            triggered_flaws=tuple(triggered_flaws),
            outcome_hints={
                "operation_type": operation_type.value,
                "difficulty": difficulty.value,
            },
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _rng_for(self, label: str, endpoint_id: str, salt: str) -> random.Random:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        seed_bytes = hashlib.sha256(f"{label}:{endpoint_id}:{day}:{salt}".encode()).digest()
        return random.Random(int.from_bytes(seed_bytes[:8], "big"))

    def _render_headers(
        self,
        raw_headers: dict[str, str],
        *,
        endpoint_id: str,
        salt: str,
    ) -> dict[str, str]:
        rendered: dict[str, str] = {}
        for key, value in (raw_headers or {}).items():
            rendered[str(key)] = self._render_header_value(str(value), endpoint_id=endpoint_id, salt=salt)
        return rendered

    def _render_header_value(self, value: str, *, endpoint_id: str, salt: str) -> str:
        if value == "{{uuid}}":
            rng = self._rng_for("header_uuid", endpoint_id, salt)
            return str(uuid.UUID(int=rng.getrandbits(128)))

        match = _INT_TEMPLATE_RE.match(value or "")
        if match:
            lo = int(match.group(1))
            hi = int(match.group(2))
            if hi < lo:
                lo, hi = hi, lo
            rng = self._rng_for(f"header_int:{value}", endpoint_id, salt)
            return str(rng.randint(lo, hi))

        return value

    def _should_error_bias(self, endpoint: EffectiveEndpoint, salt: str) -> bool:
        """Error_bias profile: ~50% chance of returning an error response."""
        if "error_trap" not in endpoint.response.profile_id:
            return False
        rng = self._rng_for("ebias", endpoint.endpoint_id, salt)
        return rng.random() < 0.5

    def _pick_error_status(self, endpoint: EffectiveEndpoint, salt: str) -> int:
        rng = self._rng_for("estatus", endpoint.endpoint_id, salt)
        return rng.choice([400, 401, 403, 429, 500, 502, 503])

    def _error_payload(self, endpoint: EffectiveEndpoint, status_code: int) -> dict:
        messages = {
            400: "Bad request",
            401: "Authentication required",
            403: "Access denied",
            429: "Too many requests",
            500: "Internal server error",
            502: "Bad gateway",
            503: "Service temporarily unavailable",
        }
        detail = messages.get(status_code, "An error occurred")
        return {"error": detail, "status": status_code}

    def _sample_latency(self, endpoint: EffectiveEndpoint, salt: str) -> int:
        """Sample a latency from the profile range using a stable seed."""
        lat = endpoint.response.latency
        if lat.min_ms >= lat.max_ms:
            return lat.min_ms
        rng = self._rng_for("lat", endpoint.endpoint_id, salt)
        return rng.randint(lat.min_ms, lat.max_ms)


# ── Module-level singleton ────────────────────────────────────────────────────

_factory = ResponseFactory()


def build_response(
    effective_endpoint: EffectiveEndpoint,
    *,
    salt: str = "",
) -> Optional[ResponseSpec]:
    """Module-level entry point. Returns None if endpoint not supported.

    Use this from response_bridge. Never raises.
    """
    try:
        return _factory.build(effective_endpoint, salt=salt)
    except Exception:
        import logging
        logging.getLogger(__name__).debug(
            "ResponseFactory.build failed for endpoint_id=%r",
            getattr(effective_endpoint, "endpoint_id", "?"),
            exc_info=True,
        )
        return None
