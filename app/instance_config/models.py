"""Instance configuration models — the DB side of the domain.

These models represent how a SPECIFIC deployed instance is configured.
They are:
  - Mutable (operators change them at runtime via the panel).
  - Persisted in the DB (system_settings table, key="instance_config").
  - NEVER merged with catalog logic here — that happens in the builder.

Design rules:
  - Every field is Optional with a sensible default meaning "use catalog default".
  - EndpointConfig.flaw_profile_id = None → inherit from template.
  - EndpointConfig.flaw_profile_id = ""   → explicitly disabled (no flaw).
  - EndpointConfig.response_profile_id = None → inherit from endpoint definition.

The canonical serialisation format is JSON (stored in system_settings).
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, field_validator, model_validator

from app.catalog.types import Difficulty


class EndpointConfig(BaseModel):
    """Per-endpoint overrides. Stored inside InstanceConfig.endpoint_configs.

    All fields are optional:
      None   → use the catalog/template default.
      ""     → explicitly disable (only for flaw_profile_id).
      value  → override with this value.

    endpoint_id: must match an EndpointDefinition.id in the registry.
                 Validated by the builder, not here (no catalog dependency).
    """
    endpoint_id: str
    enabled: bool = True

    # None  = inherit from endpoint definition default
    response_profile_id: Optional[str] = None

    # None  = inherit from template default
    # ""    = explicitly disable flaw for this endpoint
    # "xyz" = use flaw profile with id "xyz"
    flaw_profile_id: Optional[str] = None

    # None = use profile latency
    fixed_status: Optional[int] = None
    latency_ms: Optional[int] = None

    # Merged on top of profile's default_headers
    extra_headers: dict[str, str] = {}

    updated_at: Optional[str] = None

    @field_validator("endpoint_id")
    @classmethod
    def _non_empty_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("endpoint_id must not be empty")
        return v

    @field_validator("fixed_status")
    @classmethod
    def _valid_status(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (100 <= v <= 599):
            raise ValueError(f"fixed_status must be 100–599, got {v}")
        return v

    @field_validator("latency_ms")
    @classmethod
    def _non_negative_latency(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 0:
            raise ValueError(f"latency_ms must be ≥ 0, got {v}")
        return v

    @property
    def flaw_explicitly_disabled(self) -> bool:
        """True when flaw_profile_id = "" (empty string = intentional disable)."""
        return self.flaw_profile_id == ""


class InstanceConfig(BaseModel):
    """Top-level instance configuration. One per deployed instance.

    Persisted as JSON under system_settings key "instance_config".

    base_template_id:       Which template to use. Must exist in catalog.
    enabled_extension_ids:  Extensions to activate. Must be compatible with template.
    global_difficulty:      Fallback difficulty when no profile override is specified.
    endpoint_configs:       Per-endpoint overrides, keyed by endpoint_id.
    """
    base_template_id: str
    enabled_extension_ids: list[str] = []
    global_difficulty: Difficulty = Difficulty.MEDIUM
    endpoint_configs: dict[str, EndpointConfig] = {}

    @field_validator("base_template_id")
    @classmethod
    def _non_empty_template(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("base_template_id must not be empty")
        return v

    @model_validator(mode="after")
    def _endpoint_configs_keys_match_values(self) -> "InstanceConfig":
        for key, cfg in self.endpoint_configs.items():
            if key != cfg.endpoint_id:
                raise ValueError(
                    f"endpoint_configs key '{key}' does not match "
                    f"EndpointConfig.endpoint_id '{cfg.endpoint_id}'"
                )
        return self

    # ── Convenience helpers ───────────────────────────────────────────────────

    def get_endpoint_config(self, endpoint_id: str) -> Optional[EndpointConfig]:
        return self.endpoint_configs.get(endpoint_id)

    def with_endpoint_config(self, config: EndpointConfig) -> "InstanceConfig":
        """Return a new InstanceConfig with this endpoint config upserted."""
        updated = dict(self.endpoint_configs)
        updated[config.endpoint_id] = config
        return self.model_copy(update={"endpoint_configs": updated})

    def without_endpoint_config(self, endpoint_id: str) -> "InstanceConfig":
        """Return a new InstanceConfig with this endpoint config removed."""
        updated = {k: v for k, v in self.endpoint_configs.items() if k != endpoint_id}
        return self.model_copy(update={"endpoint_configs": updated})

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str) -> "InstanceConfig":
        return cls.model_validate_json(raw)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InstanceConfig":
        return cls.model_validate(data)

    # ── Default instance ──────────────────────────────────────────────────────

    @classmethod
    def default(cls) -> "InstanceConfig":
        """Minimal valid config. Uses ecommerce template, no extensions, no overrides."""
        return cls(base_template_id="ecommerce")
