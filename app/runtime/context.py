"""InteractionContext — semantic context of a single interaction.

This is NOT a replacement for the events table. It is a rich semantic
annotation attached to each request that enriches extra_json.

Purpose:
  - Actor scoring:   endpoint_id + operation_type → derive scoring kind
  - Case evidence:   semantic tagging beyond raw path/method
  - Session replay:  full context reconstruction
  - Campaigns:       feature extraction (template_id, flaw_ids, surface_type)

Usage pattern (inside log_all_requests middleware):

    ctx = InteractionContext(
        endpoint_id=...,
        operation_type=...,
        ...
    )
    extra_json["interaction"] = ctx.to_extra_json_fragment()

The events pipeline (insert_event, bump_actor, scoring) is NOT touched.
This is additive metadata only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.catalog.types import OperationType, ResourceType, SensitivityLevel, SurfaceType


@dataclass(frozen=True)
class InteractionOutcome:
    """Result of the interaction from the server's perspective."""
    status_code: int
    response_bytes: int
    latency_ms: int
    flaw_triggered: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class InteractionContext:
    """Semantic context of one HTTP interaction against the honeypot.

    All fields are value types (strings, tuples) — safe to freeze and hash.

    This struct is built AFTER the response is sent (inside the finally
    block of the request middleware), using the EffectiveEndpoint that
    was selected for this request.

    Fields:
      endpoint_id         Stable id from EndpointDefinition.
      operation_type      What the endpoint does (auth_login, object_read…).
      surface_type        Exposure surface (public_api, admin, internal…).
      resource_type       What data type was operated on (user, order…).
      sensitivity_level   How sensitive this endpoint is.
      template_id         Which template is active for this instance.
      extension_ids       Which extensions contributed this endpoint (if any).
      triggered_flaws     flaw_profile_ids that fired during this interaction.
      outcome             HTTP result.
    """
    endpoint_id: str
    operation_type: OperationType
    surface_type: SurfaceType
    resource_type: ResourceType
    sensitivity_level: SensitivityLevel
    template_id: str
    extension_ids: tuple[str, ...]
    triggered_flaws: tuple[str, ...]
    outcome: InteractionOutcome

    def to_extra_json_fragment(self) -> dict[str, Any]:
        """Serialise to a dict fragment suitable for events.extra_json.

        The calling code merges this into the existing extra_json dict;
        it does not replace it.

        Schema (stable — all keys always present):
          endpoint_id       str   — stable catalog id
          operation_type    str   — semantic operation (auth_login, object_read…)
          surface_type      str   — exposure surface (public_api, admin…)
          resource_type     str   — data type (user, order, secret…)
          sensitivity_level str   — low | medium | high | critical
          template_id       str   — active template for this instance
          extension_ids     list  — extension packs contributing this endpoint
          triggered_flaws   list  — flaw_profile_ids that fired
          status_code       int   — HTTP status of the response
          latency_ms        int   — total request latency in ms
          response_bytes    int   — response body size in bytes (0 if unknown)
          flaw_triggered    bool  — true when any flaw fired
        """
        return {
            "endpoint_id": self.endpoint_id,
            "operation_type": self.operation_type.value,
            "surface_type": self.surface_type.value,
            "resource_type": self.resource_type.value,
            "sensitivity_level": self.sensitivity_level.value,
            "template_id": self.template_id,
            "extension_ids": list(self.extension_ids),
            "triggered_flaws": list(self.triggered_flaws),
            # Outcome fields — always present (0 / False for unknowns)
            "status_code": self.outcome.status_code,
            "latency_ms": self.outcome.latency_ms,
            "response_bytes": self.outcome.response_bytes,
            "flaw_triggered": self.outcome.flaw_triggered,
        }

    @classmethod
    def from_effective_endpoint(
        cls,
        *,
        endpoint_id: str,
        operation_type: OperationType,
        surface_type: SurfaceType,
        resource_type: ResourceType,
        sensitivity_level: SensitivityLevel,
        template_id: str,
        extension_ids: tuple[str, ...],
        triggered_flaws: tuple[str, ...],
        outcome: InteractionOutcome,
    ) -> "InteractionContext":
        """Named-argument constructor to avoid positional mistakes."""
        return cls(
            endpoint_id=endpoint_id,
            operation_type=operation_type,
            surface_type=surface_type,
            resource_type=resource_type,
            sensitivity_level=sensitivity_level,
            template_id=template_id,
            extension_ids=extension_ids,
            triggered_flaws=triggered_flaws,
            outcome=outcome,
        )
