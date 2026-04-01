"""build_effective_runtime_config — the bridge between catalog+config and runtime.

This is a pure function:
  (CatalogRegistry, InstanceConfig) → EffectiveRuntimeConfig

It is the ONLY place where catalog and instance config are combined.
After this function returns, the runtime sees only EffectiveRuntimeConfig.

Precedence (highest → lowest):
  1. instance_config.endpoint_configs[ep_id]   (user override)
  2. template.default_flaw_profile_id          (template default, compatibility-gated)
  3. endpoint.default_response_profile_id      (endpoint default)
  4. global_difficulty                          (fallback difficulty hint)

Conflict policy:
  - Explicit user flaw override incompatible with endpoint → BuildError (hard fail).
  - Template default flaw incompatible with endpoint → WARNING + skip (soft fail).
  - Extension endpoint id already claimed by template → BuildError (hard fail).
  - Incompatible extensions enabled together → BuildError (hard fail).
  - Missing dependency for extension → BuildError (hard fail).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from app.catalog.definitions import (
    EndpointDefinition,
    ResponseProfileDefinition,
    SecurityFlawProfileDefinition,
)
from app.catalog.registry import CatalogRegistry
from app.catalog.types import Difficulty, FlawKind
from app.instance_config.models import EndpointConfig, InstanceConfig
from app.runtime.models import (
    EffectiveEndpoint,
    EffectiveFlaw,
    EffectiveLatency,
    EffectiveResponseConfig,
    EffectiveRuntimeConfig,
)

logger = logging.getLogger(__name__)


class BuildError(Exception):
    """Raised when InstanceConfig is inconsistent with the catalog.

    These are operator configuration errors. The application should log
    them prominently and refuse to serve requests with a broken config.
    """


# ── Internal helpers ──────────────────────────────────────────────────────────

def _difficulty_to_richness(difficulty: Difficulty) -> int:
    return {
        Difficulty.BASIC: 1,
        Difficulty.MEDIUM: 2,
        Difficulty.ADVANCED: 3,
    }.get(difficulty, 2)


def _resolve_response_profile(
    profile_id: str,
    registry: CatalogRegistry,
    context: str,
    max_depth: int = 5,
) -> ResponseProfileDefinition:
    """Walk the parent_id inheritance chain; child always wins.

    context: human-readable string for error messages (e.g. "endpoint 'orders_get'")
    """
    chain: list[ResponseProfileDefinition] = []
    seen: set[str] = set()
    current_id: Optional[str] = profile_id

    while current_id and len(chain) < max_depth:
        if current_id in seen:
            raise BuildError(
                f"Circular inheritance in response profiles at '{current_id}' "
                f"(context: {context})"
            )
        seen.add(current_id)
        profile = registry.get_response_profile(current_id)
        if not profile:
            raise BuildError(
                f"Response profile '{current_id}' not found in catalog "
                f"(context: {context})"
            )
        chain.append(profile)
        current_id = profile.parent_id

    # chain[0] is the most specific (the one requested)
    return chain[0]


def _build_effective_response(
    endpoint: EndpointDefinition,
    profile: ResponseProfileDefinition,
    ep_config: Optional[EndpointConfig],
) -> EffectiveResponseConfig:
    """Merge endpoint config overrides onto a resolved response profile."""
    # Latency: user override wins; otherwise use profile range
    if ep_config is not None and ep_config.latency_ms is not None:
        latency = EffectiveLatency(
            min_ms=ep_config.latency_ms,
            max_ms=ep_config.latency_ms,
            p99_ms=ep_config.latency_ms,
        )
    else:
        latency = EffectiveLatency(
            min_ms=profile.latency.min_ms,
            max_ms=profile.latency.max_ms,
            p99_ms=profile.latency.p99_ms,
        )

    # Headers: profile defaults, then user extra_headers on top
    headers = dict(profile.default_headers)
    if ep_config is not None:
        headers.update(ep_config.extra_headers)

    fixed_status: Optional[int] = ep_config.fixed_status if ep_config is not None else None

    return EffectiveResponseConfig(
        profile_id=profile.id,
        difficulty=profile.difficulty,
        headers=headers,
        latency=latency,
        fixed_status=fixed_status,
        error_format=profile.error_style.format,
        richness_level=_difficulty_to_richness(profile.difficulty),
    )


def _build_effective_flaw(
    endpoint: EndpointDefinition,
    flaw_profile_id: str,
    registry: CatalogRegistry,
    *,
    is_user_override: bool,
) -> Optional[EffectiveFlaw]:
    """Build EffectiveFlaw, enforcing compatibility.

    is_user_override=True  → incompatibility raises BuildError (hard fail).
    is_user_override=False → incompatibility logs WARNING and returns None.
    """
    flaw = registry.get_flaw_profile(flaw_profile_id)
    if not flaw:
        msg = (
            f"Flaw profile '{flaw_profile_id}' not found in catalog "
            f"(endpoint '{endpoint.id}')"
        )
        if is_user_override:
            raise BuildError(msg)
        logger.warning(msg)
        return None

    # Check endpoint's flaw allow-list
    if flaw_profile_id not in endpoint.supported_flaw_profile_ids:
        msg = (
            f"Flaw '{flaw_profile_id}' is not in supported_flaw_profile_ids "
            f"of endpoint '{endpoint.id}' "
            f"(supported: {endpoint.supported_flaw_profile_ids})"
        )
        if is_user_override:
            raise BuildError(msg)
        logger.warning("Skipping incompatible template flaw: %s", msg)
        return None

    # Check operation_type compatibility
    if (
        flaw.compatible_operation_types
        and endpoint.operation_type not in flaw.compatible_operation_types
    ):
        msg = (
            f"Flaw '{flaw_profile_id}' (kind={flaw.kind.value}) is incompatible "
            f"with operation_type '{endpoint.operation_type.value}' on endpoint "
            f"'{endpoint.id}'. Compatible types: "
            f"{[t.value for t in flaw.compatible_operation_types]}"
        )
        if is_user_override:
            raise BuildError(msg)
        logger.warning("Skipping incompatible template flaw: %s", msg)
        return None

    return EffectiveFlaw(
        profile_id=flaw.id,
        kind=flaw.kind,
        parameters=dict(flaw.parameters),
        ttp_tags=flaw.ttp_tags,
        detection_markers=flaw.detection_markers,
    )


def _resolve_extension_load_order(
    extension_ids: list[str],
    registry: CatalogRegistry,
) -> list[str]:
    """Topological sort of extensions respecting declared dependencies.

    Returns extension ids ordered so every dep comes before its dependant.
    Raises BuildError on cycles or unsatisfied dependencies.
    """
    resolved: list[str] = []
    visited: set[str] = set()
    visiting: set[str] = set()  # grey set for cycle detection

    def visit(ext_id: str) -> None:
        if ext_id in visited:
            return
        if ext_id in visiting:
            raise BuildError(
                f"Circular dependency detected in extensions at '{ext_id}'"
            )
        ext = registry.get_extension(ext_id)
        if not ext:
            raise BuildError(f"Extension '{ext_id}' not found in catalog")

        visiting.add(ext_id)
        for dep_id in ext.dependencies:
            if dep_id not in extension_ids:
                raise BuildError(
                    f"Extension '{ext_id}' requires '{dep_id}' which is not enabled"
                )
            visit(dep_id)
        visiting.discard(ext_id)
        visited.add(ext_id)
        resolved.append(ext_id)

    for eid in extension_ids:
        visit(eid)

    return resolved


def _validate_extension_compatibility(
    extension_ids: list[str],
    registry: CatalogRegistry,
) -> None:
    """Raise BuildError if any pair of enabled extensions is incompatible."""
    ext_set = set(extension_ids)
    for eid in extension_ids:
        ext = registry.get_extension(eid)
        if not ext:
            raise BuildError(f"Extension '{eid}' not found in catalog")
        for incompat_id in ext.incompatible_with:
            if incompat_id in ext_set:
                raise BuildError(
                    f"Extensions '{eid}' and '{incompat_id}' are mutually "
                    f"incompatible and cannot both be enabled"
                )


# ── Main entry point ──────────────────────────────────────────────────────────

def build_effective_runtime_config(
    instance_config: InstanceConfig,
    registry: CatalogRegistry,
) -> EffectiveRuntimeConfig:
    """Pure function: (InstanceConfig, CatalogRegistry) → EffectiveRuntimeConfig.

    Steps:
      1. Resolve template.
      2. Validate and order extensions (topological sort + compatibility check).
      3. Validate extensions are compatible with this template.
      4. Collect all endpoint definitions (template groups + extension groups).
         - Conflicts (same endpoint_id from two sources) → BuildError.
      5. For each endpoint:
         a. Determine enabled state.
         b. Resolve response profile (precedence chain).
         c. Resolve flaw profile (precedence chain + compatibility check).
         d. Build EffectiveEndpoint.
      6. Wrap in EffectiveRuntimeConfig.
    """
    # ── 1. Template ────────────────────────────────────────────────────────────
    template = registry.get_template(instance_config.base_template_id)
    if not template:
        raise BuildError(
            f"Template '{instance_config.base_template_id}' not found in catalog"
        )

    # ── 2. Extensions ──────────────────────────────────────────────────────────
    ext_ids = list(instance_config.enabled_extension_ids)
    _validate_extension_compatibility(ext_ids, registry)
    ordered_ext_ids = _resolve_extension_load_order(ext_ids, registry)

    # ── 3. Template ↔ extension compatibility ─────────────────────────────────
    for eid in ext_ids:
        if eid not in template.compatible_extension_ids:
            raise BuildError(
                f"Extension '{eid}' is not listed as compatible with template "
                f"'{instance_config.base_template_id}'. "
                f"Compatible: {list(template.compatible_extension_ids)}"
            )

    # ── 4. Collect endpoints ───────────────────────────────────────────────────
    # Maps endpoint_id → (definition, source_label)
    endpoint_sources: dict[str, tuple[EndpointDefinition, str]] = {}

    for ep in registry.endpoints_for_template(instance_config.base_template_id):
        endpoint_sources[ep.id] = (ep, f"template:{instance_config.base_template_id}")

    for eid in ordered_ext_ids:
        for ep in registry.endpoints_for_extension(eid):
            if ep.id in endpoint_sources:
                _, existing_src = endpoint_sources[ep.id]
                raise BuildError(
                    f"Endpoint '{ep.id}' from extension '{eid}' conflicts with "
                    f"endpoint already provided by '{existing_src}'. "
                    f"Extensions cannot override template endpoints unless "
                    f"merge_rules.allow_path_override=True (not yet supported)."
                )
            endpoint_sources[ep.id] = (ep, f"extension:{eid}")

    # ── 5. Build effective endpoints ───────────────────────────────────────────
    effective_endpoints: dict[str, EffectiveEndpoint] = {}

    for ep_id, (ep_def, source_label) in endpoint_sources.items():
        ep_config: Optional[EndpointConfig] = instance_config.endpoint_configs.get(ep_id)

        # a. Enabled state
        enabled = ep_config.enabled if ep_config is not None else True

        # b. Response profile (precedence: user override → endpoint default)
        if ep_config is not None and ep_config.response_profile_id:
            response_profile_id = ep_config.response_profile_id
        else:
            response_profile_id = ep_def.default_response_profile_id

        resolved_profile = _resolve_response_profile(
            response_profile_id, registry,
            context=f"endpoint '{ep_id}'",
        )
        effective_response = _build_effective_response(ep_def, resolved_profile, ep_config)

        # c. Flaw profile
        #    Precedence: user override (ep_config) → template default → None
        effective_flaw: Optional[EffectiveFlaw] = None

        if ep_config is not None and ep_config.flaw_profile_id is not None:
            # User has explicitly set a flaw (or "" to disable)
            if ep_config.flaw_explicitly_disabled:
                effective_flaw = None  # intentionally disabled
            else:
                effective_flaw = _build_effective_flaw(
                    ep_def, ep_config.flaw_profile_id, registry,
                    is_user_override=True,  # hard fail on incompatibility
                )
        elif template.default_flaw_profile_id:
            # Template default: soft fail (skip silently if incompatible)
            effective_flaw = _build_effective_flaw(
                ep_def, template.default_flaw_profile_id, registry,
                is_user_override=False,  # warning + skip on incompatibility
            )

        # d. Provenance
        ext_provenance: tuple[str, ...] = ()
        if source_label.startswith("extension:"):
            ext_provenance = (source_label.split(":", 1)[1],)

        effective_endpoints[ep_id] = EffectiveEndpoint(
            endpoint_id=ep_id,
            method=ep_def.method,
            path_pattern=ep_def.path_pattern,
            operation_type=ep_def.operation_type,
            surface_type=ep_def.surface_type,
            resource_type=ep_def.resource_type,
            sensitivity_level=ep_def.sensitivity_level,
            enabled=enabled,
            include_in_schema=ep_def.include_in_schema,
            response=effective_response,
            flaw=effective_flaw,
            template_id=instance_config.base_template_id,
            extension_ids=ext_provenance,
        )

    # ── 6. Wrap ────────────────────────────────────────────────────────────────
    return EffectiveRuntimeConfig(
        endpoints=effective_endpoints,
        template_id=instance_config.base_template_id,
        extension_ids=tuple(ordered_ext_ids),
        global_difficulty=instance_config.global_difficulty,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
