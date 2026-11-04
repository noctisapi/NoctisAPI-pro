"""Tests for CatalogRegistry validation and lookup logic.

No DB, no env vars, no imports from honeypot_public or panel_mvp.
"""
import pytest

from app.catalog.builtin.loader import build_default_registry
from app.catalog.definitions import (
    BaseTemplateDefinition,
    EndpointDefinition,
    EndpointGroupDefinition,
    ExtensionPackDefinition,
    LatencyConfig,
    MergeRules,
    ResponseProfileDefinition,
    SecurityFlawProfileDefinition,
)
from app.catalog.registry import CatalogRegistry, CatalogValidationError
from app.catalog.types import (
    Difficulty,
    FlawKind,
    HttpMethod,
    OperationType,
    ResourceType,
    SensitivityLevel,
    SurfaceType,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def minimal_registry() -> CatalogRegistry:
    """A registry with one profile, one flaw, one endpoint, one group."""
    reg = CatalogRegistry()
    reg.register_response_profile(ResponseProfileDefinition(
        id="rp_base", name="Base", difficulty=Difficulty.MEDIUM,
    ))
    reg.register_flaw_profile(SecurityFlawProfileDefinition(
        id="flaw_idor", name="IDOR", kind=FlawKind.IDOR,
        compatible_operation_types=(OperationType.OBJECT_READ,),
    ))
    reg.register_endpoint(EndpointDefinition(
        id="ep_one", method=HttpMethod.GET, path_pattern="/ep/one",
        operation_type=OperationType.OBJECT_READ,
        surface_type=SurfaceType.PUBLIC_API,
        resource_type=ResourceType.GENERIC,
        sensitivity_level=SensitivityLevel.LOW,
        default_response_profile_id="rp_base",
        supported_flaw_profile_ids=("flaw_idor",),
    ))
    reg.register_group(EndpointGroupDefinition(
        id="grp_one", name="Group One", endpoint_ids=("ep_one",),
    ))
    return reg


# ── Definition model validation ───────────────────────────────────────────────

class TestLatencyConfig:
    def test_valid_latency(self):
        lc = LatencyConfig(min_ms=10, max_ms=100, p99_ms=500)
        assert lc.min_ms == 10

    def test_min_gt_max_raises(self):
        with pytest.raises(ValueError, match="min_ms"):
            LatencyConfig(min_ms=200, max_ms=100, p99_ms=500)

    def test_max_gt_p99_raises(self):
        with pytest.raises(ValueError, match="max_ms"):
            LatencyConfig(min_ms=10, max_ms=600, p99_ms=500)


class TestEndpointDefinition:
    def test_path_must_start_with_slash(self):
        with pytest.raises(ValueError, match="start with '/'"):
            EndpointDefinition(
                id="bad_ep", method=HttpMethod.GET, path_pattern="no-slash",
                operation_type=OperationType.OBJECT_READ,
                surface_type=SurfaceType.PUBLIC_API,
                resource_type=ResourceType.GENERIC,
                sensitivity_level=SensitivityLevel.LOW,
                default_response_profile_id="rp",
            )

    def test_id_cannot_have_spaces(self):
        with pytest.raises(ValueError, match="no spaces"):
            EndpointDefinition(
                id="bad id", method=HttpMethod.GET, path_pattern="/x",
                operation_type=OperationType.OBJECT_READ,
                surface_type=SurfaceType.PUBLIC_API,
                resource_type=ResourceType.GENERIC,
                sensitivity_level=SensitivityLevel.LOW,
                default_response_profile_id="rp",
            )


# ── CatalogRegistry — uniqueness constraints ──────────────────────────────────

class TestRegistryUniqueness:
    def test_duplicate_response_profile_raises(self, minimal_registry):
        with pytest.raises(CatalogValidationError, match="already registered"):
            minimal_registry.register_response_profile(ResponseProfileDefinition(
                id="rp_base", name="Duplicate", difficulty=Difficulty.BASIC,
            ))

    def test_duplicate_flaw_profile_raises(self, minimal_registry):
        with pytest.raises(CatalogValidationError, match="already registered"):
            minimal_registry.register_flaw_profile(SecurityFlawProfileDefinition(
                id="flaw_idor", name="Duplicate", kind=FlawKind.IDOR,
            ))

    def test_duplicate_endpoint_id_raises(self, minimal_registry):
        with pytest.raises(CatalogValidationError, match="already registered"):
            minimal_registry.register_endpoint(EndpointDefinition(
                id="ep_one", method=HttpMethod.POST, path_pattern="/ep/other",
                operation_type=OperationType.OBJECT_CREATE,
                surface_type=SurfaceType.PUBLIC_API,
                resource_type=ResourceType.GENERIC,
                sensitivity_level=SensitivityLevel.LOW,
                default_response_profile_id="rp_base",
            ))

    def test_duplicate_path_different_id_raises(self, minimal_registry):
        """Same (method, path) but different id → explicit conflict error."""
        with pytest.raises(CatalogValidationError, match="Path conflict"):
            minimal_registry.register_endpoint(EndpointDefinition(
                id="ep_two", method=HttpMethod.GET, path_pattern="/ep/one",
                operation_type=OperationType.OBJECT_READ,
                surface_type=SurfaceType.PUBLIC_API,
                resource_type=ResourceType.GENERIC,
                sensitivity_level=SensitivityLevel.LOW,
                default_response_profile_id="rp_base",
            ))

    def test_same_path_different_method_is_ok(self, minimal_registry):
        """POST /ep/one can coexist with GET /ep/one."""
        minimal_registry.register_endpoint(EndpointDefinition(
            id="ep_post_one", method=HttpMethod.POST, path_pattern="/ep/one",
            operation_type=OperationType.OBJECT_CREATE,
            surface_type=SurfaceType.PUBLIC_API,
            resource_type=ResourceType.GENERIC,
            sensitivity_level=SensitivityLevel.LOW,
            default_response_profile_id="rp_base",
        ))  # must not raise


# ── CatalogRegistry — reference validation ────────────────────────────────────

class TestRegistryReferences:
    def test_endpoint_unknown_response_profile_raises(self):
        reg = CatalogRegistry()
        with pytest.raises(CatalogValidationError, match="unknown response_profile"):
            reg.register_endpoint(EndpointDefinition(
                id="ep_x", method=HttpMethod.GET, path_pattern="/x",
                operation_type=OperationType.OBJECT_READ,
                surface_type=SurfaceType.PUBLIC_API,
                resource_type=ResourceType.GENERIC,
                sensitivity_level=SensitivityLevel.LOW,
                default_response_profile_id="nonexistent",
            ))

    def test_endpoint_unknown_flaw_profile_raises(self):
        reg = CatalogRegistry()
        reg.register_response_profile(ResponseProfileDefinition(
            id="rp", name="RP", difficulty=Difficulty.MEDIUM,
        ))
        with pytest.raises(CatalogValidationError, match="unknown flaw_profile"):
            reg.register_endpoint(EndpointDefinition(
                id="ep_x", method=HttpMethod.GET, path_pattern="/x",
                operation_type=OperationType.OBJECT_READ,
                surface_type=SurfaceType.PUBLIC_API,
                resource_type=ResourceType.GENERIC,
                sensitivity_level=SensitivityLevel.LOW,
                default_response_profile_id="rp",
                supported_flaw_profile_ids=("nonexistent_flaw",),
            ))

    def test_group_unknown_endpoint_raises(self, minimal_registry):
        with pytest.raises(CatalogValidationError, match="unknown endpoint"):
            minimal_registry.register_group(EndpointGroupDefinition(
                id="grp_bad", name="Bad", endpoint_ids=("ep_ghost",),
            ))

    def test_template_unknown_group_raises(self, minimal_registry):
        with pytest.raises(CatalogValidationError, match="unknown group"):
            minimal_registry.register_template(BaseTemplateDefinition(
                id="tmpl", name="T",
                endpoint_group_ids=("ghost_group",),
                default_response_profile_id="rp_base",
            ))

    def test_extension_unknown_group_raises(self, minimal_registry):
        with pytest.raises(CatalogValidationError, match="unknown group"):
            minimal_registry.register_extension(ExtensionPackDefinition(
                id="ext_bad", name="Bad",
                endpoint_group_ids=("ghost_group",),
            ))


# ── CatalogRegistry — validate_all ────────────────────────────────────────────

class TestValidateAll:
    def test_circular_profile_inheritance_raises(self):
        reg = CatalogRegistry()
        reg.register_response_profile(ResponseProfileDefinition(
            id="rp_a", name="A", difficulty=Difficulty.BASIC, parent_id="rp_b",
        ))
        reg.register_response_profile(ResponseProfileDefinition(
            id="rp_b", name="B", difficulty=Difficulty.MEDIUM, parent_id="rp_a",
        ))
        with pytest.raises(CatalogValidationError, match="Circular inheritance"):
            reg.validate_all()

    def test_extension_unknown_dep_raises(self):
        reg = CatalogRegistry()
        reg.register_extension(ExtensionPackDefinition(
            id="ext_a", name="A", dependencies=("ghost_dep",),
        ))
        with pytest.raises(CatalogValidationError, match="unknown extension"):
            reg.validate_all()

    def test_extension_unknown_incompatible_raises(self):
        reg = CatalogRegistry()
        reg.register_extension(ExtensionPackDefinition(
            id="ext_a", name="A", incompatible_with=("ghost_ext",),
        ))
        with pytest.raises(CatalogValidationError, match="unknown incompatible"):
            reg.validate_all()

    def test_template_unknown_compatible_ext_raises(self):
        reg = CatalogRegistry()
        reg.register_response_profile(ResponseProfileDefinition(
            id="rp", name="RP", difficulty=Difficulty.MEDIUM,
        ))
        reg.register_template(BaseTemplateDefinition(
            id="tmpl", name="T",
            endpoint_group_ids=(),
            default_response_profile_id="rp",
            compatible_extension_ids=("ghost_ext",),
        ))
        with pytest.raises(CatalogValidationError, match="unknown compatible extension"):
            reg.validate_all()


# ── CatalogRegistry — lookups ─────────────────────────────────────────────────

class TestRegistryLookups:
    def test_get_endpoint_by_id(self, minimal_registry):
        ep = minimal_registry.get_endpoint("ep_one")
        assert ep is not None
        assert ep.path_pattern == "/ep/one"

    def test_get_endpoint_by_path(self, minimal_registry):
        ep = minimal_registry.get_endpoint_by_path("GET", "/ep/one")
        assert ep is not None
        assert ep.id == "ep_one"

    def test_get_endpoint_by_path_case_insensitive_method(self, minimal_registry):
        ep = minimal_registry.get_endpoint_by_path("get", "/ep/one")
        assert ep is not None

    def test_get_nonexistent_returns_none(self, minimal_registry):
        assert minimal_registry.get_endpoint("ghost") is None
        assert minimal_registry.get_endpoint_by_path("GET", "/ghost") is None

    def test_endpoints_for_template(self, minimal_registry):
        minimal_registry.register_template(BaseTemplateDefinition(
            id="tmpl", name="T",
            endpoint_group_ids=("grp_one",),
            default_response_profile_id="rp_base",
        ))
        endpoints = minimal_registry.endpoints_for_template("tmpl")
        assert len(endpoints) == 1
        assert endpoints[0].id == "ep_one"


# ── Built-in registry smoke test ─────────────────────────────────────────────

class TestDefaultRegistry:
    def test_builds_without_error(self):
        registry = build_default_registry()
        s = registry.summary()
        assert s["endpoints"] > 0
        assert s["templates"] >= 2
        assert s["extensions"] >= 2

    def test_ecommerce_template_exists(self):
        registry = build_default_registry()
        tmpl = registry.get_template("ecommerce")
        assert tmpl is not None
        assert len(tmpl.endpoint_group_ids) > 0

    def test_critical_endpoints_registered(self):
        registry = build_default_registry()
        for ep_id in ("auth_login", "orders_get", "secrets_admin", "backup_download"):
            assert registry.get_endpoint(ep_id) is not None, f"Missing: {ep_id}"

    def test_no_path_conflicts_in_builtins(self):
        """Smoke test: building the registry implies no path conflicts."""
        registry = build_default_registry()
        assert registry.summary()["endpoints"] > 0  # already passed validate_all

    def test_flaw_profiles_compatible_with_endpoints(self):
        """Every flaw referenced by an endpoint's supported list must exist."""
        registry = build_default_registry()
        for ep_id in (
            "orders_get", "users_get", "auth_login", "backup_download", "files_download"
        ):
            ep = registry.get_endpoint(ep_id)
            assert ep is not None
            for flaw_id in ep.supported_flaw_profile_ids:
                flaw = registry.get_flaw_profile(flaw_id)
                assert flaw is not None, f"Endpoint '{ep_id}' references unknown flaw '{flaw_id}'"
