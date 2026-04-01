"""CatalogRegistry — the in-memory, validated catalog of all definitions.

Responsibilities:
  - Accept registrations of all catalog entities.
  - Enforce cross-reference integrity (no dangling references).
  - Enforce uniqueness constraints (no duplicate ids, no path conflicts).
  - Provide lookup methods for the builder.

Loaded ONCE at startup. After validate_all() succeeds, the registry is
treated as immutable. The builder only reads from it, never writes.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.catalog.definitions import (
    BaseTemplateDefinition,
    EndpointDefinition,
    EndpointGroupDefinition,
    ExtensionPackDefinition,
    ResponseProfileDefinition,
    SecurityFlawProfileDefinition,
)

logger = logging.getLogger(__name__)


class CatalogValidationError(Exception):
    """Raised when the catalog contains an invalid or inconsistent definition.

    These are programmer errors (wrong catalog setup), not runtime errors.
    The application should refuse to start if catalog validation fails.
    """


class CatalogRegistry:
    """Immutable-after-validate catalog of all system definitions.

    Registration order matters for cross-reference validation:
      1. register_response_profile / register_flaw_profile  (no deps)
      2. register_endpoint                                   (needs profiles)
      3. register_group                                      (needs endpoints)
      4. register_extension                                  (needs groups)
      5. register_template                                   (needs groups + profiles)
      6. validate_all()                                      (final check)
    """

    def __init__(self) -> None:
        self._endpoints: dict[str, EndpointDefinition] = {}
        self._groups: dict[str, EndpointGroupDefinition] = {}
        self._templates: dict[str, BaseTemplateDefinition] = {}
        self._extensions: dict[str, ExtensionPackDefinition] = {}
        self._response_profiles: dict[str, ResponseProfileDefinition] = {}
        self._flaw_profiles: dict[str, SecurityFlawProfileDefinition] = {}
        # (method_upper, path_pattern) → endpoint_id — for conflict detection
        self._path_index: dict[tuple[str, str], str] = {}

    # ── Registration ──────────────────────────────────────────────────────────

    def register_response_profile(self, profile: ResponseProfileDefinition) -> None:
        if profile.id in self._response_profiles:
            raise CatalogValidationError(
                f"ResponseProfile '{profile.id}' is already registered"
            )
        self._response_profiles[profile.id] = profile

    def register_flaw_profile(self, profile: SecurityFlawProfileDefinition) -> None:
        if profile.id in self._flaw_profiles:
            raise CatalogValidationError(
                f"SecurityFlawProfile '{profile.id}' is already registered"
            )
        self._flaw_profiles[profile.id] = profile

    def register_endpoint(self, endpoint: EndpointDefinition) -> None:
        # Unique id
        if endpoint.id in self._endpoints:
            raise CatalogValidationError(
                f"Endpoint id '{endpoint.id}' is already registered"
            )
        # Unique (method, path) — no silent ambiguity
        path_key = (endpoint.method.value, endpoint.path_pattern)
        if path_key in self._path_index:
            existing = self._path_index[path_key]
            raise CatalogValidationError(
                f"Path conflict: {endpoint.method.value} {endpoint.path_pattern!r} "
                f"is already claimed by endpoint '{existing}' — "
                f"cannot also register '{endpoint.id}'"
            )
        # Default response profile must exist at registration time
        if endpoint.default_response_profile_id not in self._response_profiles:
            raise CatalogValidationError(
                f"Endpoint '{endpoint.id}' references unknown response_profile "
                f"'{endpoint.default_response_profile_id}'"
            )
        # Supported flaw profiles must exist at registration time
        for fid in endpoint.supported_flaw_profile_ids:
            if fid not in self._flaw_profiles:
                raise CatalogValidationError(
                    f"Endpoint '{endpoint.id}' references unknown flaw_profile '{fid}'"
                )
        self._endpoints[endpoint.id] = endpoint
        self._path_index[path_key] = endpoint.id

    def register_group(self, group: EndpointGroupDefinition) -> None:
        if group.id in self._groups:
            raise CatalogValidationError(
                f"EndpointGroup '{group.id}' is already registered"
            )
        for ep_id in group.endpoint_ids:
            if ep_id not in self._endpoints:
                raise CatalogValidationError(
                    f"Group '{group.id}' references unknown endpoint '{ep_id}'"
                )
        self._groups[group.id] = group

    def register_template(self, template: BaseTemplateDefinition) -> None:
        if template.id in self._templates:
            raise CatalogValidationError(
                f"Template '{template.id}' is already registered"
            )
        for gid in template.endpoint_group_ids:
            if gid not in self._groups:
                raise CatalogValidationError(
                    f"Template '{template.id}' references unknown group '{gid}'"
                )
        if template.default_response_profile_id not in self._response_profiles:
            raise CatalogValidationError(
                f"Template '{template.id}' references unknown response_profile "
                f"'{template.default_response_profile_id}'"
            )
        if template.default_flaw_profile_id and template.default_flaw_profile_id not in self._flaw_profiles:
            raise CatalogValidationError(
                f"Template '{template.id}' references unknown flaw_profile "
                f"'{template.default_flaw_profile_id}'"
            )
        self._templates[template.id] = template

    def register_extension(self, extension: ExtensionPackDefinition) -> None:
        if extension.id in self._extensions:
            raise CatalogValidationError(
                f"Extension '{extension.id}' is already registered"
            )
        for gid in extension.endpoint_group_ids:
            if gid not in self._groups:
                raise CatalogValidationError(
                    f"Extension '{extension.id}' references unknown group '{gid}'"
                )
        self._extensions[extension.id] = extension

    # ── Cross-reference validation (call after all registrations) ────────────

    def validate_all(self) -> None:
        """Run full referential integrity check.

        Call this once after all registrations. Raises CatalogValidationError
        on any problem. The application MUST NOT start if this fails.
        """
        self._validate_response_profile_inheritance()
        self._validate_extension_cross_references()
        self._validate_template_extension_compatibility()

    def _validate_response_profile_inheritance(self) -> None:
        for pid, prof in self._response_profiles.items():
            if prof.parent_id is None:
                continue
            if prof.parent_id not in self._response_profiles:
                raise CatalogValidationError(
                    f"ResponseProfile '{pid}' inherits from unknown profile '{prof.parent_id}'"
                )
            # Detect cycles
            visited: set[str] = set()
            current: Optional[str] = pid
            while current:
                if current in visited:
                    raise CatalogValidationError(
                        f"Circular inheritance detected in response profiles starting at '{pid}'"
                    )
                visited.add(current)
                current = self._response_profiles[current].parent_id

    def _validate_extension_cross_references(self) -> None:
        for eid, ext in self._extensions.items():
            for dep_id in ext.dependencies:
                if dep_id not in self._extensions:
                    raise CatalogValidationError(
                        f"Extension '{eid}' depends on unknown extension '{dep_id}'"
                    )
            for incompat_id in ext.incompatible_with:
                if incompat_id not in self._extensions:
                    raise CatalogValidationError(
                        f"Extension '{eid}' lists unknown incompatible extension '{incompat_id}'"
                    )

    def _validate_template_extension_compatibility(self) -> None:
        for tid, tmpl in self._templates.items():
            for eid in tmpl.compatible_extension_ids:
                if eid not in self._extensions:
                    raise CatalogValidationError(
                        f"Template '{tid}' lists unknown compatible extension '{eid}'"
                    )

    # ── Lookups ───────────────────────────────────────────────────────────────

    def get_endpoint(self, endpoint_id: str) -> Optional[EndpointDefinition]:
        return self._endpoints.get(endpoint_id)

    def get_endpoint_by_path(self, method: str, path: str) -> Optional[EndpointDefinition]:
        ep_id = self._path_index.get((method.upper(), path))
        return self._endpoints.get(ep_id) if ep_id else None

    def get_group(self, group_id: str) -> Optional[EndpointGroupDefinition]:
        return self._groups.get(group_id)

    def get_template(self, template_id: str) -> Optional[BaseTemplateDefinition]:
        return self._templates.get(template_id)

    def get_extension(self, ext_id: str) -> Optional[ExtensionPackDefinition]:
        return self._extensions.get(ext_id)

    def get_response_profile(self, profile_id: str) -> Optional[ResponseProfileDefinition]:
        return self._response_profiles.get(profile_id)

    def get_flaw_profile(self, flaw_id: str) -> Optional[SecurityFlawProfileDefinition]:
        return self._flaw_profiles.get(flaw_id)

    def endpoints_for_template(self, template_id: str) -> list[EndpointDefinition]:
        """Returns all endpoints contributed by a template's groups (deduped, ordered)."""
        tmpl = self._templates.get(template_id)
        if not tmpl:
            return []
        result: list[EndpointDefinition] = []
        seen: set[str] = set()
        for gid in tmpl.endpoint_group_ids:
            group = self._groups.get(gid)
            if not group:
                continue
            for ep_id in group.endpoint_ids:
                if ep_id not in seen:
                    ep = self._endpoints.get(ep_id)
                    if ep:
                        result.append(ep)
                        seen.add(ep_id)
        return result

    def endpoints_for_extension(self, ext_id: str) -> list[EndpointDefinition]:
        """Returns all endpoints contributed by an extension's groups (deduped, ordered)."""
        ext = self._extensions.get(ext_id)
        if not ext:
            return []
        result: list[EndpointDefinition] = []
        seen: set[str] = set()
        for gid in ext.endpoint_group_ids:
            group = self._groups.get(gid)
            if not group:
                continue
            for ep_id in group.endpoint_ids:
                if ep_id not in seen:
                    ep = self._endpoints.get(ep_id)
                    if ep:
                        result.append(ep)
                        seen.add(ep_id)
        return result

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def summary(self) -> dict[str, int]:
        return {
            "response_profiles": len(self._response_profiles),
            "flaw_profiles": len(self._flaw_profiles),
            "endpoints": len(self._endpoints),
            "groups": len(self._groups),
            "templates": len(self._templates),
            "extensions": len(self._extensions),
        }
