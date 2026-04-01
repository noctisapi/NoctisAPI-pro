"""Loads all built-in definitions into a CatalogRegistry.

Call build_default_registry() once at application startup.
The result is then passed to the runtime builder.

Registration order is important (see CatalogRegistry docstring):
  1. Response profiles   (no deps)
  2. Flaw profiles       (no deps)
  3. Endpoints           (need profiles)
  4. Groups              (need endpoints)
  5. Extensions          (need groups)
  6. Templates           (need groups, profiles)
  7. validate_all()
"""
from __future__ import annotations

from app.catalog.builtin.endpoint_groups import ALL_ENDPOINT_DEFINITIONS, ALL_GROUP_DEFINITIONS
from app.catalog.builtin.extensions import ALL_EXTENSIONS
from app.catalog.builtin.flaw_profiles import ALL_FLAW_PROFILES
from app.catalog.builtin.response_profiles import ALL_RESPONSE_PROFILES
from app.catalog.builtin.templates import ALL_TEMPLATES
from app.catalog.registry import CatalogRegistry


def build_default_registry() -> CatalogRegistry:
    """Build and validate the default catalog registry.

    Raises CatalogValidationError if any definition is invalid or
    cross-references are broken. Call this at startup and fail fast.
    """
    registry = CatalogRegistry()

    for profile in ALL_RESPONSE_PROFILES:
        registry.register_response_profile(profile)

    for flaw in ALL_FLAW_PROFILES:
        registry.register_flaw_profile(flaw)

    for endpoint in ALL_ENDPOINT_DEFINITIONS:
        registry.register_endpoint(endpoint)

    for group in ALL_GROUP_DEFINITIONS:
        registry.register_group(group)

    for extension in ALL_EXTENSIONS:
        registry.register_extension(extension)

    for template in ALL_TEMPLATES:
        registry.register_template(template)

    registry.validate_all()
    return registry
