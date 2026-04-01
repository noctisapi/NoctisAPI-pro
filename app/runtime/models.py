"""Runtime domain models - the fully resolved state that request handling uses."""
from __future__ import annotations

from dataclasses import dataclass
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


@dataclass
class EffectiveLatency:
    min_ms: int
    max_ms: int
    p99_ms: int


@dataclass
class EffectiveResponseConfig:
    """Fully resolved response presentation for one endpoint."""

    profile_id: str
    difficulty: Difficulty
    headers: dict[str, str]
    latency: EffectiveLatency
    fixed_status: Optional[int]
    error_format: str
    richness_level: int  # 0-2, compatible with the legacy body shaping scale


@dataclass
class EffectiveFlaw:
    profile_id: str
    kind: FlawKind
    parameters: dict[str, Any]
    ttp_tags: tuple[str, ...]
    detection_markers: tuple[str, ...]


@dataclass
class EffectiveMutationConfig:
    policy: str
    intensity: int

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "mutation_policy": self.policy,
            "mutation_intensity": self.intensity,
        }


@dataclass
class EffectiveResponseRuleMatch:
    endpoint_id: Optional[str]
    endpoint_group_id: Optional[str]
    method: Optional[str]
    user_agent_contains: Optional[str]


@dataclass
class EffectiveResponseRuleAction:
    richness_delta: Optional[int]
    force_status: Optional[int]
    extra_latency_ms: Optional[int]


@dataclass
class EffectiveResponseRule:
    id: str
    enabled: bool
    match: EffectiveResponseRuleMatch
    action: EffectiveResponseRuleAction
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class EffectiveEndpoint:
    """Single endpoint, fully resolved."""

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
    template_id: str
    extension_ids: tuple[str, ...]
    group_ids: tuple[str, ...] = ()
    has_instance_override: bool = False


@dataclass
class EffectiveRuntimeConfig:
    """The single entry point for runtime logic."""

    endpoints: dict[str, EffectiveEndpoint]
    template_id: str
    extension_ids: tuple[str, ...]
    global_difficulty: Difficulty
    mutation_config: EffectiveMutationConfig
    response_rules: tuple[EffectiveResponseRule, ...]
    generated_at: str

    def get_endpoint(self, endpoint_id: str) -> Optional[EffectiveEndpoint]:
        return self.endpoints.get(endpoint_id)

    def get_endpoint_by_path(self, method: str, path: str) -> Optional[EffectiveEndpoint]:
        method_upper = method.upper()
        for endpoint in self.endpoints.values():
            if endpoint.method.value == method_upper and endpoint.path_pattern == path:
                return endpoint
        return None

    def enabled_endpoints(self) -> list[EffectiveEndpoint]:
        return [endpoint for endpoint in self.endpoints.values() if endpoint.enabled]

    def stats(self) -> dict[str, Any]:
        total = len(self.endpoints)
        enabled = sum(1 for endpoint in self.endpoints.values() if endpoint.enabled)
        flawed = sum(1 for endpoint in self.endpoints.values() if endpoint.flaw is not None)
        return {
            "template_id": self.template_id,
            "extension_ids": list(self.extension_ids),
            "total_endpoints": total,
            "enabled_endpoints": enabled,
            "disabled_endpoints": total - enabled,
            "endpoints_with_flaw": flawed,
            "global_difficulty": self.global_difficulty.value,
            "mutation_policy": self.mutation_config.policy,
            "mutation_intensity": self.mutation_config.intensity,
            "response_rules": len(self.response_rules),
            "generated_at": self.generated_at,
        }
