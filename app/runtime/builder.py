"""Build the effective runtime config from catalog + instance config."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from app.catalog.definitions import EndpointDefinition, ResponseProfileDefinition
from app.catalog.registry import CatalogRegistry
from app.catalog.types import Difficulty
from app.instance_config.models import EndpointConfig, InstanceConfig
from app.runtime.models import (
    EffectiveEndpoint,
    EffectiveFlaw,
    EffectiveLatency,
    EffectiveMutationConfig,
    EffectiveResponseConfig,
    EffectiveResponseRule,
    EffectiveResponseRuleAction,
    EffectiveResponseRuleMatch,
    EffectiveRuntimeConfig,
)

logger = logging.getLogger(__name__)


class BuildError(Exception):
    """Raised when InstanceConfig is inconsistent with the catalog."""


def _difficulty_to_richness(difficulty: Difficulty) -> int:
    if difficulty == Difficulty.BASIC:
        return 0
    return 2


def _resolve_response_profile(
    profile_id: str,
    registry: CatalogRegistry,
    context: str,
    max_depth: int = 5,
) -> ResponseProfileDefinition:
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

    return chain[0]


def _build_effective_response(
    endpoint: EndpointDefinition,
    profile: ResponseProfileDefinition,
    ep_config: Optional[EndpointConfig],
) -> EffectiveResponseConfig:
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

    headers = dict(profile.default_headers)
    if ep_config is not None:
        headers.update(ep_config.extra_headers)

    fixed_status = ep_config.fixed_status if ep_config is not None else None

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
    flaw = registry.get_flaw_profile(flaw_profile_id)
    if not flaw:
        message = (
            f"Flaw profile '{flaw_profile_id}' not found in catalog "
            f"(endpoint '{endpoint.id}')"
        )
        if is_user_override:
            raise BuildError(message)
        logger.warning(message)
        return None

    if flaw_profile_id not in endpoint.supported_flaw_profile_ids:
        message = (
            f"Flaw '{flaw_profile_id}' is not in supported_flaw_profile_ids "
            f"of endpoint '{endpoint.id}' "
            f"(supported: {endpoint.supported_flaw_profile_ids})"
        )
        if is_user_override:
            raise BuildError(message)
        logger.warning("Skipping incompatible template flaw: %s", message)
        return None

    if flaw.compatible_operation_types and endpoint.operation_type not in flaw.compatible_operation_types:
        message = (
            f"Flaw '{flaw_profile_id}' is incompatible with operation_type "
            f"'{endpoint.operation_type.value}' on endpoint '{endpoint.id}'"
        )
        if is_user_override:
            raise BuildError(message)
        logger.warning("Skipping incompatible template flaw: %s", message)
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
    resolved: list[str] = []
    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(ext_id: str) -> None:
        if ext_id in visited:
            return
        if ext_id in visiting:
            raise BuildError(f"Circular dependency detected in extensions at '{ext_id}'")

        ext = registry.get_extension(ext_id)
        if not ext:
            raise BuildError(f"Extension '{ext_id}' not found in catalog")

        visiting.add(ext_id)
        for dependency_id in ext.dependencies:
            if dependency_id not in extension_ids:
                raise BuildError(
                    f"Extension '{ext_id}' requires '{dependency_id}' which is not enabled"
                )
            visit(dependency_id)
        visiting.remove(ext_id)
        visited.add(ext_id)
        resolved.append(ext_id)

    for extension_id in extension_ids:
        visit(extension_id)
    return resolved


def _validate_extension_compatibility(extension_ids: list[str], registry: CatalogRegistry) -> None:
    ext_set = set(extension_ids)
    for extension_id in extension_ids:
        extension = registry.get_extension(extension_id)
        if not extension:
            raise BuildError(f"Extension '{extension_id}' not found in catalog")
        for incompatible_id in extension.incompatible_with:
            if incompatible_id in ext_set:
                raise BuildError(
                    f"Extensions '{extension_id}' and '{incompatible_id}' are mutually incompatible"
                )


def _build_group_membership(
    instance_config: InstanceConfig,
    ordered_ext_ids: list[str],
    registry: CatalogRegistry,
) -> dict[str, tuple[str, ...]]:
    endpoint_groups: dict[str, list[str]] = {}

    template = registry.get_template(instance_config.base_template_id)
    if template:
        for group_id in template.endpoint_group_ids:
            group = registry.get_group(group_id)
            if not group:
                continue
            for endpoint_id in group.endpoint_ids:
                endpoint_groups.setdefault(endpoint_id, []).append(group_id)

    for extension_id in ordered_ext_ids:
        extension = registry.get_extension(extension_id)
        if not extension:
            continue
        for group_id in extension.endpoint_group_ids:
            group = registry.get_group(group_id)
            if not group:
                continue
            for endpoint_id in group.endpoint_ids:
                endpoint_groups.setdefault(endpoint_id, []).append(group_id)

    return {endpoint_id: tuple(group_ids) for endpoint_id, group_ids in endpoint_groups.items()}


def build_effective_runtime_config(
    instance_config: InstanceConfig,
    registry: CatalogRegistry,
) -> EffectiveRuntimeConfig:
    template = registry.get_template(instance_config.base_template_id)
    if not template:
        raise BuildError(f"Template '{instance_config.base_template_id}' not found in catalog")

    ext_ids = list(instance_config.enabled_extension_ids)
    _validate_extension_compatibility(ext_ids, registry)
    ordered_ext_ids = _resolve_extension_load_order(ext_ids, registry)

    for extension_id in ext_ids:
        if extension_id not in template.compatible_extension_ids:
            raise BuildError(
                f"Extension '{extension_id}' is not listed as compatible with template "
                f"'{instance_config.base_template_id}'. Compatible: {list(template.compatible_extension_ids)}"
            )

    endpoint_sources: dict[str, tuple[EndpointDefinition, str]] = {}
    for endpoint in registry.endpoints_for_template(instance_config.base_template_id):
        endpoint_sources[endpoint.id] = (endpoint, f"template:{instance_config.base_template_id}")

    for extension_id in ordered_ext_ids:
        for endpoint in registry.endpoints_for_extension(extension_id):
            if endpoint.id in endpoint_sources:
                _, existing_source = endpoint_sources[endpoint.id]
                raise BuildError(
                    f"Endpoint '{endpoint.id}' from extension '{extension_id}' conflicts with "
                    f"endpoint already provided by '{existing_source}'"
                )
            endpoint_sources[endpoint.id] = (endpoint, f"extension:{extension_id}")

    endpoint_groups = _build_group_membership(instance_config, ordered_ext_ids, registry)
    effective_endpoints: dict[str, EffectiveEndpoint] = {}

    for endpoint_id, (endpoint_def, source_label) in endpoint_sources.items():
        endpoint_config = instance_config.endpoint_configs.get(endpoint_id)
        enabled = endpoint_config.enabled if endpoint_config is not None else True

        if endpoint_config is not None and endpoint_config.response_profile_id:
            response_profile_id = endpoint_config.response_profile_id
        else:
            response_profile_id = endpoint_def.default_response_profile_id

        resolved_profile = _resolve_response_profile(
            response_profile_id,
            registry,
            context=f"endpoint '{endpoint_id}'",
        )
        effective_response = _build_effective_response(endpoint_def, resolved_profile, endpoint_config)

        effective_flaw: Optional[EffectiveFlaw] = None
        if endpoint_config is not None and endpoint_config.flaw_profile_id is not None:
            if endpoint_config.flaw_explicitly_disabled:
                effective_flaw = None
            else:
                effective_flaw = _build_effective_flaw(
                    endpoint_def,
                    endpoint_config.flaw_profile_id,
                    registry,
                    is_user_override=True,
                )
        elif template.default_flaw_profile_id:
            effective_flaw = _build_effective_flaw(
                endpoint_def,
                template.default_flaw_profile_id,
                registry,
                is_user_override=False,
            )

        extension_ids: tuple[str, ...] = ()
        if source_label.startswith("extension:"):
            extension_ids = (source_label.split(":", 1)[1],)

        effective_endpoints[endpoint_id] = EffectiveEndpoint(
            endpoint_id=endpoint_id,
            method=endpoint_def.method,
            path_pattern=endpoint_def.path_pattern,
            operation_type=endpoint_def.operation_type,
            surface_type=endpoint_def.surface_type,
            resource_type=endpoint_def.resource_type,
            sensitivity_level=endpoint_def.sensitivity_level,
            enabled=enabled,
            include_in_schema=endpoint_def.include_in_schema,
            response=effective_response,
            flaw=effective_flaw,
            template_id=instance_config.base_template_id,
            extension_ids=extension_ids,
            group_ids=endpoint_groups.get(endpoint_id, ()),
            has_instance_override=endpoint_config is not None,
        )

    effective_rules: list[EffectiveResponseRule] = []
    for index, rule in enumerate(instance_config.response_rules, start=1):
        rule_id = rule.id or f"rule_{index}"
        effective_rules.append(
            EffectiveResponseRule(
                id=rule_id,
                enabled=bool(rule.enabled),
                match=EffectiveResponseRuleMatch(
                    endpoint_id=rule.match.endpoint_id,
                    endpoint_group_id=rule.match.endpoint_group_id,
                    method=rule.match.method,
                    user_agent_contains=rule.match.user_agent_contains,
                ),
                action=EffectiveResponseRuleAction(
                    richness_delta=rule.action.richness_delta,
                    force_status=rule.action.force_status,
                    extra_latency_ms=rule.action.extra_latency_ms,
                ),
                created_at=rule.created_at,
                updated_at=rule.updated_at,
            )
        )

    return EffectiveRuntimeConfig(
        endpoints=effective_endpoints,
        template_id=instance_config.base_template_id,
        extension_ids=tuple(ordered_ext_ids),
        global_difficulty=instance_config.global_difficulty,
        mutation_config=EffectiveMutationConfig(
            policy=instance_config.mutation_config.policy,
            intensity=instance_config.mutation_config.intensity,
        ),
        response_rules=tuple(effective_rules),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
