"""Catalog entity definitions — immutable, code-only.

All models here are frozen Pydantic models. They represent what CAN
exist in the system. They are NEVER persisted to DB; they live in code.

Design rules:
  - No default values that read env vars or DB.
  - No circular references.
  - IDs are stable strings, not derived from paths.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, field_validator, model_validator

from app.catalog.types import Difficulty, FlawKind, HttpMethod, OperationType, ResourceType, SensitivityLevel, SurfaceType


# ── Value objects ─────────────────────────────────────────────────────────────

class LatencyConfig(BaseModel, frozen=True):
    """Latency profile for a response.

    min_ms ≤ max_ms ≤ p99_ms is enforced at construction.
    """
    min_ms: int = 0
    max_ms: int = 200
    p99_ms: int = 500

    @model_validator(mode="after")
    def _check_order(self) -> "LatencyConfig":
        if self.min_ms > self.max_ms:
            raise ValueError(f"min_ms ({self.min_ms}) > max_ms ({self.max_ms})")
        if self.max_ms > self.p99_ms:
            raise ValueError(f"max_ms ({self.max_ms}) > p99_ms ({self.p99_ms})")
        return self


class ErrorStyleConfig(BaseModel, frozen=True):
    """How errors are formatted in responses."""
    format: str = "json"             # "json" | "html" | "plain"
    include_stack_trace: bool = False
    randomize_message: bool = True

    @field_validator("format")
    @classmethod
    def _check_format(cls, v: str) -> str:
        allowed = {"json", "html", "plain"}
        if v not in allowed:
            raise ValueError(f"format must be one of {allowed}, got {v!r}")
        return v


class MergeRules(BaseModel, frozen=True):
    """Controls how an extension's endpoints integrate with the base template."""
    # priority: lower number = applied first; higher = can shadow earlier
    priority: int = 0
    # If True, the extension may provide an endpoint with the same path as the
    # template (overriding its response config). Default: False (conflict = error).
    allow_path_override: bool = False


# ── ResponseProfileDefinition ─────────────────────────────────────────────────

class ResponseProfileDefinition(BaseModel, frozen=True):
    """Defines how an endpoint's response *looks*.

    Reusable across endpoints. Supports single-parent inheritance:
    child fields take precedence over parent fields.

    Catalog concept — NOT about what data the endpoint returns,
    only about HOW it's packaged (latency, headers, error style, richness).
    """
    id: str
    name: str
    difficulty: Difficulty
    latency: LatencyConfig = LatencyConfig()
    error_style: ErrorStyleConfig = ErrorStyleConfig()
    default_headers: dict[str, str] = {}
    # Inheritance: reference another ResponseProfileDefinition.id
    parent_id: Optional[str] = None
    description: str = ""

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("id and name must be non-empty strings")
        return v


# ── SecurityFlawProfileDefinition ─────────────────────────────────────────────

class SecurityFlawProfileDefinition(BaseModel, frozen=True):
    """Defines a *security vulnerability behavior* to simulate.

    IMPORTANT: completely separate from ResponseProfileDefinition.
    A flaw changes the *semantic* behavior (leaks extra data, accepts bad
    input, ignores auth) while a response profile changes *presentation*
    (headers, latency, error format).

    compatible_operation_types: if non-empty, this flaw can only be
    applied to endpoints with one of these operation_types. Enforced by
    the builder.
    """
    id: str
    name: str
    kind: FlawKind
    parameters: dict[str, Any] = {}
    compatible_operation_types: tuple[OperationType, ...] = ()
    ttp_tags: tuple[str, ...] = ()
    detection_markers: tuple[str, ...] = ()
    description: str = ""

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("id and name must be non-empty strings")
        return v


# ── EndpointDefinition ────────────────────────────────────────────────────────

class EndpointDefinition(BaseModel, frozen=True):
    """Core catalog entity. Represents ONE endpoint of the honeypot API.

    WHY this eliminates route-hardcoding:
      The system no longer derives endpoint identity from (method, path).
      Instead, identity is `id` — a stable string like "orders_get_by_id".
      This means:
        - Path can be refactored without losing DB config.
        - Endpoint config is stored/queried by id, not by URL.
        - The router is generated FROM the catalog, not coded separately.

    HOW it's used at runtime:
      1. CatalogRegistry holds all EndpointDefinitions.
      2. InstanceConfig (DB) holds per-id overrides.
      3. builder.build_effective_runtime_config() combines both into
         EffectiveRuntimeConfig, keyed by endpoint_id.
      4. The router iterates EffectiveRuntimeConfig.endpoints to register
         routes dynamically — zero hardcoded routes.

    Fields:
      id                       Stable identifier. NEVER change after deploy.
      method                   HTTP method.
      path_pattern             FastAPI/Starlette path pattern (can include {params}).
      operation_type           Semantic classification (auth_login, object_read…).
      surface_type             Who calls this (public_api, admin, internal…).
      resource_type            What it operates on (user, order, secret…).
      sensitivity_level        How dangerous access is.
      default_response_profile_id  ResponseProfileDefinition.id to use if not overridden.
      supported_flaw_profile_ids   Allow-list of flaws that CAN be applied to this endpoint.
                               The builder will reject any flaw not in this list.
      tags                     Free-form labels (ttp_hints, case_hints, ATT&CK refs…).
      include_in_schema        Whether to expose in OpenAPI spec.
    """
    id: str
    method: HttpMethod
    path_pattern: str
    operation_type: OperationType
    surface_type: SurfaceType
    resource_type: ResourceType
    sensitivity_level: SensitivityLevel
    default_response_profile_id: str
    supported_flaw_profile_ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    include_in_schema: bool = True
    description: str = ""

    @field_validator("id")
    @classmethod
    def _id_no_spaces(cls, v: str) -> str:
        if not v.strip() or " " in v:
            raise ValueError("endpoint id must be non-empty and contain no spaces")
        return v

    @field_validator("path_pattern")
    @classmethod
    def _path_starts_with_slash(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError(f"path_pattern must start with '/', got {v!r}")
        return v


# ── EndpointGroupDefinition ───────────────────────────────────────────────────

class EndpointGroupDefinition(BaseModel, frozen=True):
    """A named set of endpoints that belong together logically.

    Templates and extensions reference groups, not individual endpoints.
    This allows a template to say "include the auth_flows group" without
    enumerating every endpoint inside it.
    """
    id: str
    name: str
    endpoint_ids: tuple[str, ...] = ()
    description: str = ""


# ── BaseTemplateDefinition ────────────────────────────────────────────────────

class BaseTemplateDefinition(BaseModel, frozen=True):
    """Represents a *type of application* being simulated.

    Examples: "ecommerce", "corporate_saas", "cloud_platform", "devops_portal".

    A template:
      - Includes a set of endpoint groups (its surface area).
      - Sets a default response profile (difficulty / presentation).
      - Optionally sets a default flaw profile applied to all compatible endpoints.
      - Declares which extensions are compatible.

    EXACTLY ONE template is active per instance (set in InstanceConfig).
    Templates are EXCLUSIVE — you cannot combine two templates.
    """
    id: str
    name: str
    description: str = ""
    endpoint_group_ids: tuple[str, ...] = ()
    default_response_profile_id: str
    # If set, this flaw is applied by default to all endpoints that support it.
    # Can be overridden per-endpoint in InstanceConfig.
    default_flaw_profile_id: Optional[str] = None
    compatible_extension_ids: tuple[str, ...] = ()


# ── ExtensionPackDefinition ───────────────────────────────────────────────────

class ExtensionPackDefinition(BaseModel, frozen=True):
    """An optional set of additional endpoint groups added ON TOP of a template.

    An extension is NOT a full template — it cannot exist alone.
    It only adds endpoint groups; it cannot override or remove endpoints
    already defined by the base template (unless allow_path_override=True
    in merge_rules, which is an explicit opt-in).

    dependencies:      other extension IDs that MUST be enabled first.
    incompatible_with: extensions that CANNOT be enabled at the same time.
    merge_rules:       controls how conflicts are resolved.
    """
    id: str
    name: str
    description: str = ""
    endpoint_group_ids: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    incompatible_with: tuple[str, ...] = ()
    merge_rules: MergeRules = MergeRules()
