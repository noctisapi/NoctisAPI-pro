"""Instance configuration models for the DB-backed configuration layer.

These models represent how a specific deployed instance is configured.
They are:
  - Mutable (operators change them at runtime via the panel).
  - Persisted in the DB (system_settings table, key="instance_config").
  - Independent from catalog/runtime resolution logic.

Design rules:
  - Every field is optional or has a safe default meaning "use inherited value".
  - EndpointConfig.flaw_profile_id = None -> inherit from template.
  - EndpointConfig.flaw_profile_id = ""   -> explicitly disable (no flaw).
  - EndpointConfig.response_profile_id = None -> inherit from endpoint definition.

The canonical serialisation format is JSON (stored in system_settings).
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.catalog.types import Difficulty

_MUTATION_POLICIES = {"none", "daily", "weekly"}


class EndpointConfig(BaseModel):
    """Per-endpoint overrides stored inside InstanceConfig.endpoint_configs."""

    endpoint_id: str
    enabled: bool = True

    # None = inherit from endpoint definition default
    response_profile_id: Optional[str] = None

    # None  = inherit from template default
    # ""    = explicitly disable flaw for this endpoint
    # "xyz" = use flaw profile with id "xyz"
    flaw_profile_id: Optional[str] = None

    # None = use profile latency / natural status
    fixed_status: Optional[int] = None
    latency_ms: Optional[int] = None

    # Merged on top of profile default headers
    extra_headers: dict[str, str] = Field(default_factory=dict)

    updated_at: Optional[str] = None

    @field_validator("endpoint_id")
    @classmethod
    def _non_empty_id(cls, value: str) -> str:
        if not str(value or "").strip():
            raise ValueError("endpoint_id must not be empty")
        return str(value).strip()

    @field_validator("fixed_status")
    @classmethod
    def _valid_status(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and not (100 <= int(value) <= 599):
            raise ValueError(f"fixed_status must be 100-599, got {value}")
        return value

    @field_validator("latency_ms")
    @classmethod
    def _non_negative_latency(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and int(value) < 0:
            raise ValueError(f"latency_ms must be >= 0, got {value}")
        return value

    @property
    def flaw_explicitly_disabled(self) -> bool:
        return self.flaw_profile_id == ""


class MutationConfig(BaseModel):
    """Global mutation policy applied after endpoint resolution."""

    policy: str = "none"
    intensity: int = 0

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            normalized = dict(data)
            if "policy" not in normalized and "mutation_policy" in normalized:
                normalized["policy"] = normalized.get("mutation_policy")
            if "intensity" not in normalized and "mutation_intensity" in normalized:
                normalized["intensity"] = normalized.get("mutation_intensity")
            return normalized
        return data

    @field_validator("policy")
    @classmethod
    def _valid_policy(cls, value: str) -> str:
        normalized = str(value or "none").strip().lower()
        if normalized not in _MUTATION_POLICIES:
            raise ValueError(f"mutation policy must be one of {_MUTATION_POLICIES}")
        return normalized

    @field_validator("intensity")
    @classmethod
    def _valid_intensity(cls, value: int) -> int:
        parsed = int(value or 0)
        if not (0 <= parsed <= 3):
            raise ValueError("mutation intensity must be 0..3")
        return parsed

    def to_legacy_dict(self) -> dict[str, Any]:
        return {
            "mutation_policy": self.policy,
            "mutation_intensity": self.intensity,
        }


class ResponseRuleMatch(BaseModel):
    """Semantic rule target based on endpoint ids instead of raw paths."""

    endpoint_id: Optional[str] = None
    endpoint_group_id: Optional[str] = None
    method: Optional[str] = None
    user_agent_contains: Optional[str] = None

    @field_validator("endpoint_id", "endpoint_group_id", "user_agent_contains")
    @classmethod
    def _empty_to_none(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @field_validator("method")
    @classmethod
    def _normalize_method(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().upper()
        return text or None

    @model_validator(mode="after")
    def _requires_endpoint_scope(self) -> "ResponseRuleMatch":
        if not self.endpoint_id and not self.endpoint_group_id:
            raise ValueError("response rule match requires endpoint_id or endpoint_group_id")
        return self


class ResponseRuleAction(BaseModel):
    """Response mutations applied when a rule matches."""

    richness_delta: Optional[int] = None
    force_status: Optional[int] = None
    extra_latency_ms: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            normalized = dict(data)
            if "richness_delta" not in normalized and "change_richness" in normalized:
                normalized["richness_delta"] = normalized.get("change_richness")
            if "extra_latency_ms" not in normalized and "increase_latency" in normalized:
                normalized["extra_latency_ms"] = normalized.get("increase_latency")
            return normalized
        return data

    @field_validator("richness_delta")
    @classmethod
    def _valid_richness_delta(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        parsed = int(value)
        if not (-2 <= parsed <= 2):
            raise ValueError("richness_delta must be between -2 and 2")
        return parsed

    @field_validator("force_status")
    @classmethod
    def _valid_force_status(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        parsed = int(value)
        if not (100 <= parsed <= 599):
            raise ValueError("force_status must be 100-599")
        return parsed

    @field_validator("extra_latency_ms")
    @classmethod
    def _valid_extra_latency(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        parsed = int(value)
        if not (0 <= parsed <= 5000):
            raise ValueError("extra_latency_ms must be 0..5000")
        return parsed


class ResponseRule(BaseModel):
    """Runtime-native rule definition persisted inside InstanceConfig."""

    id: Optional[str] = None
    enabled: bool = True
    match: ResponseRuleMatch
    action: ResponseRuleAction
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @field_validator("id")
    @classmethod
    def _non_empty_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            raise ValueError("rule id must not be empty")
        return text


class InstanceConfig(BaseModel):
    """Top-level instance configuration. One per deployed instance."""

    base_template_id: str
    enabled_extension_ids: list[str] = Field(default_factory=list)
    global_difficulty: Difficulty = Difficulty.MEDIUM
    endpoint_configs: dict[str, EndpointConfig] = Field(default_factory=dict)
    mutation_config: MutationConfig = Field(default_factory=MutationConfig)
    response_rules: list[ResponseRule] = Field(default_factory=list)

    @field_validator("base_template_id")
    @classmethod
    def _non_empty_template(cls, value: str) -> str:
        if not str(value or "").strip():
            raise ValueError("base_template_id must not be empty")
        return str(value).strip()

    @model_validator(mode="after")
    def _endpoint_configs_keys_match_values(self) -> "InstanceConfig":
        for key, cfg in self.endpoint_configs.items():
            if key != cfg.endpoint_id:
                raise ValueError(
                    f"endpoint_configs key '{key}' does not match "
                    f"EndpointConfig.endpoint_id '{cfg.endpoint_id}'"
                )
        return self

    def get_endpoint_config(self, endpoint_id: str) -> Optional[EndpointConfig]:
        return self.endpoint_configs.get(endpoint_id)

    def with_endpoint_config(self, config: EndpointConfig) -> "InstanceConfig":
        updated = dict(self.endpoint_configs)
        updated[config.endpoint_id] = config
        return self.model_copy(update={"endpoint_configs": updated})

    def without_endpoint_config(self, endpoint_id: str) -> "InstanceConfig":
        updated = {key: value for key, value in self.endpoint_configs.items() if key != endpoint_id}
        return self.model_copy(update={"endpoint_configs": updated})

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str) -> "InstanceConfig":
        return cls.model_validate_json(raw)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InstanceConfig":
        return cls.model_validate(data)

    @classmethod
    def default(cls) -> "InstanceConfig":
        return cls(base_template_id="ecommerce")
