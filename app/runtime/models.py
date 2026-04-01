"""Runtime domain models — the fully resolved state that route handlers see.

These are dataclasses (not Pydantic) because they are:
  - Built in memory, never serialised to DB.
  - Read-only by convention after construction.
  - Created fresh on every config rebuild.

IMPORTANT: Nothing in this file imports from app.catalog.definitions,
app.catalog.registry, or app.instance_config. The builder is the only
bridge between those layers and this one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.catalog.types import (
    Difficulty,
    FlawKind,
    HttpMethod,
    OperationType,
    ResourceType,
    SensitivityLevel,
    SurfaceType,
)


# ── Response ──────────────────────────────────────────────────────────────────

@dataclass
class EffectiveLatency:
    """Resolved latency range for a single endpoint."""
    min_ms: int
    max_ms: int
    p99_ms: int


@dataclass
class EffectiveResponseConfig:
    """Fully resolved response presentation for one endpoint.

    This is what the response generator reads. It knows NOTHING about
    templates, extensions, or override chains — all that is already
    collapsed here.
    """
    profile_id: str
    difficulty: Difficulty
    headers: dict[str, str]
    latency: EffectiveLatency
    # None  = use the natural HTTP status for the operation.
    # int   = always respond with this status code.
    fixed_status: Optional[int]
    error_format: str       # "json" | "html" | "plain"
    richness_level: int     # 0–3 (derived from difficulty)


# ── Flaw ──────────────────────────────────────────────────────────────────────

@dataclass
class EffectiveFlaw:
    """Fully resolved security flaw for one endpoint.

    Separate from EffectiveResponseConfig:
      - Response config  → HOW the response is packaged.
      - Flaw             → WHAT extra (mis)behavior is simulated.
    """
    profile_id: str
    kind: FlawKind
    parameters: dict[str, Any]
    ttp_tags: tuple[str, ...]
    detection_markers: tuple[str, ...]


# ── Endpoint ──────────────────────────────────────────────────────────────────

@dataclass
class EffectiveEndpoint:
    """Single endpoint, fully resolved. This is what route handlers use.

    Provenance fields (template_id, extension_ids) are carried for stats
    and InteractionContext — route handler logic MUST NOT branch on them.
    """
    endpoint_id: str
    method: HttpMethod
    path_pattern: str
    operation_type: OperationType
    surface_type: SurfaceType
    resource_type: ResourceType
    sensitivity_level: SensitivityLevel
    enabled: bool
    include_in_schema: bool
    response: EffectiveResponseConfig
    flaw: Optional[EffectiveFlaw]
    # Provenance — for stats/InteractionContext only
    template_id: str
    extension_ids: tuple[str, ...]


# ── Runtime config ────────────────────────────────────────────────────────────

@dataclass
class EffectiveRuntimeConfig:
    """The single entry point for all runtime logic.

    Built once by build_effective_runtime_config() and cached in memory.
    Rebuilt when the operator changes InstanceConfig.

    Route handlers use:
      config.get_endpoint(endpoint_id)          → by stable id
      config.get_endpoint_by_path(method, path) → for middleware lookup
      config.enabled_endpoints()                → for router registration

    The runtime MUST NOT read:
      - app.catalog (templates, extensions, definitions)
      - app.instance_config (overrides, raw DB config)
    Those were already collapsed during build.
    """
    endpoints: dict[str, EffectiveEndpoint]   # keyed by endpoint_id
    template_id: str
    extension_ids: tuple[str, ...]
    global_difficulty: Difficulty
    generated_at: str                          # ISO 8601

    def get_endpoint(self, endpoint_id: str) -> Optional[EffectiveEndpoint]:
        return self.endpoints.get(endpoint_id)

    def get_endpoint_by_path(self, method: str, path: str) -> Optional[EffectiveEndpoint]:
        """Linear scan — acceptable since endpoint counts are small (<200)."""
        m = method.upper()
        for ep in self.endpoints.values():
            if ep.method.value == m and ep.path_pattern == path:
                return ep
        return None

    def enabled_endpoints(self) -> list[EffectiveEndpoint]:
        return [ep for ep in self.endpoints.values() if ep.enabled]

    def stats(self) -> dict[str, Any]:
        """Diagnostic summary — useful for the health/environment panel page."""
        total = len(self.endpoints)
        enabled = sum(1 for ep in self.endpoints.values() if ep.enabled)
        flawed = sum(1 for ep in self.endpoints.values() if ep.flaw is not None)
        return {
            "template_id": self.template_id,
            "extension_ids": list(self.extension_ids),
            "total_endpoints": total,
            "enabled_endpoints": enabled,
            "disabled_endpoints": total - enabled,
            "endpoints_with_flaw": flawed,
            "global_difficulty": self.global_difficulty.value,
            "generated_at": self.generated_at,
        }
