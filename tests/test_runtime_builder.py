"""Tests for build_effective_runtime_config — the catalog+config → runtime bridge.

Covers:
  - Basic build with default ecommerce template
  - Precedence rules (user override > template default > None)
  - Flaw compatibility enforcement (hard fail for user, soft fail for template)
  - Extension handling (ordering, compatibility, conflict detection)
  - Disabled endpoint override
  - InteractionContext serialisation
"""
import pytest

from app.catalog.builtin.loader import build_default_registry
from app.catalog.definitions import (
    BaseTemplateDefinition,
    EndpointDefinition,
    EndpointGroupDefinition,
    ExtensionPackDefinition,
    ResponseProfileDefinition,
    SecurityFlawProfileDefinition,
)
from app.catalog.registry import CatalogRegistry
from app.catalog.types import (
    Difficulty,
    FlawKind,
    HttpMethod,
    OperationType,
    ResourceType,
    SensitivityLevel,
    SurfaceType,
)
from app.instance_config.models import (
    EndpointConfig,
    InstanceConfig,
    MutationConfig,
    ResponseRule,
    ResponseRuleAction,
    ResponseRuleMatch,
)
from app.runtime.builder import BuildError, build_effective_runtime_config
from app.runtime.context import InteractionContext, InteractionOutcome
from app.runtime.models import EffectiveRuntimeConfig


# ── Helpers ───────────────────────────────────────────────────────────────────

def _default_registry() -> CatalogRegistry:
    return build_default_registry()


def _default_instance() -> InstanceConfig:
    return InstanceConfig(base_template_id="ecommerce")


def _build(instance: InstanceConfig, registry: CatalogRegistry | None = None) -> EffectiveRuntimeConfig:
    return build_effective_runtime_config(instance, registry or _default_registry())


# ── Basic build ───────────────────────────────────────────────────────────────

class TestBasicBuild:
    def test_builds_without_error(self):
        config = _build(_default_instance())
        assert isinstance(config, EffectiveRuntimeConfig)

    def test_has_endpoints(self):
        config = _build(_default_instance())
        assert len(config.endpoints) > 0

    def test_template_id_propagated(self):
        config = _build(_default_instance())
        assert config.template_id == "ecommerce"

    def test_all_endpoints_have_response_config(self):
        config = _build(_default_instance())
        for ep in config.endpoints.values():
            assert ep.response is not None
            assert ep.response.profile_id != ""

    def test_endpoints_enabled_by_default(self):
        config = _build(_default_instance())
        for ep in config.endpoints.values():
            assert ep.enabled is True

    def test_generated_at_is_iso(self):
        config = _build(_default_instance())
        assert "T" in config.generated_at  # ISO 8601 contains 'T'

    def test_stats_method(self):
        config = _build(_default_instance())
        stats = config.stats()
        assert stats["total_endpoints"] == len(config.endpoints)
        assert stats["template_id"] == "ecommerce"


# ── Template default flaw ─────────────────────────────────────────────────────

class TestTemplateFlaw:
    def test_ecommerce_default_flaw_applied_to_compatible_endpoints(self):
        """ecommerce template has default_flaw_profile_id='idor_basic'.
        Endpoints that support idor_basic should have it applied."""
        config = _build(_default_instance())
        orders_get = config.get_endpoint("orders_get")
        assert orders_get is not None
        assert orders_get.flaw is not None
        assert orders_get.flaw.profile_id == "idor_basic"

    def test_template_flaw_skipped_for_incompatible_endpoint(self):
        """recon_env has no supported flaws → template default flaw is skipped, no error."""
        config = _build(_default_instance())
        recon_env = config.get_endpoint("recon_env")
        assert recon_env is not None
        assert recon_env.flaw is None  # not supported → soft skip

    def test_auth_login_gets_flaw_when_supported(self):
        """auth_login supports broken_auth_basic, sqli_hint_basic, excessive_data_basic
        but NOT idor_basic → template default idor_basic should be skipped."""
        config = _build(_default_instance())
        auth_login = config.get_endpoint("auth_login")
        assert auth_login is not None
        # idor_basic is NOT in auth_login.supported_flaw_profile_ids
        # so the template default should be skipped → flaw is None
        assert auth_login.flaw is None


# ── Precedence: user override ─────────────────────────────────────────────────

class TestUserOverridePrecedence:
    def test_user_response_profile_override_wins(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(
                    endpoint_id="orders_get",
                    response_profile_id="standard_advanced",
                )
            },
        )
        config = _build(instance)
        ep = config.get_endpoint("orders_get")
        assert ep is not None
        assert ep.response.profile_id == "standard_advanced"
        assert ep.response.difficulty == Difficulty.ADVANCED

    def test_user_flaw_override_wins_over_template(self):
        """User sets idor_advanced on orders_get (supported). Should override idor_basic."""
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(
                    endpoint_id="orders_get",
                    flaw_profile_id="idor_advanced",
                )
            },
        )
        config = _build(instance)
        ep = config.get_endpoint("orders_get")
        assert ep is not None
        assert ep.flaw is not None
        assert ep.flaw.profile_id == "idor_advanced"

    def test_user_flaw_empty_string_disables_flaw(self):
        """flaw_profile_id='' explicitly disables flaw even if template has a default."""
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(
                    endpoint_id="orders_get",
                    flaw_profile_id="",  # explicitly disabled
                )
            },
        )
        config = _build(instance)
        ep = config.get_endpoint("orders_get")
        assert ep is not None
        assert ep.flaw is None

    def test_user_disabled_endpoint(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "recon_env": EndpointConfig(endpoint_id="recon_env", enabled=False),
            },
        )
        config = _build(instance)
        ep = config.get_endpoint("recon_env")
        assert ep is not None
        assert ep.enabled is False

    def test_user_latency_override(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(endpoint_id="orders_get", latency_ms=999),
            },
        )
        config = _build(instance)
        ep = config.get_endpoint("orders_get")
        assert ep.response.latency.min_ms == 999
        assert ep.response.latency.max_ms == 999

    def test_user_fixed_status_override(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "auth_login": EndpointConfig(endpoint_id="auth_login", fixed_status=418),
            },
        )
        config = _build(instance)
        ep = config.get_endpoint("auth_login")
        assert ep.response.fixed_status == 418

    def test_user_extra_headers_merged(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(
                    endpoint_id="orders_get",
                    extra_headers={"X-Trap": "yes"},
                ),
            },
        )
        config = _build(instance)
        ep = config.get_endpoint("orders_get")
        assert ep.response.headers.get("X-Trap") == "yes"
        # Profile default headers still present
        assert "Content-Type" in ep.response.headers


# ── Flaw compatibility enforcement ────────────────────────────────────────────

class TestFlawCompatibility:
    def test_user_override_unsupported_flaw_raises(self):
        """User tries to apply idor_basic to recon_env (not supported) → hard fail."""
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "recon_env": EndpointConfig(
                    endpoint_id="recon_env",
                    flaw_profile_id="idor_basic",
                )
            },
        )
        with pytest.raises(BuildError, match="supported_flaw_profile_ids"):
            _build(instance)

    def test_user_override_wrong_operation_type_raises(self, tmp_registry):
        """idor_basic is only compatible with object_read/update/delete.
        Applying it to a RECON endpoint via user override must fail hard."""
        reg, instance = tmp_registry
        with pytest.raises(BuildError):
            build_effective_runtime_config(instance, reg)

    def test_template_flaw_incompatible_skipped_not_raised(self, caplog):
        """Template default flaw that is incompatible with an endpoint is
        silently skipped (warning logged), not a BuildError."""
        import logging
        with caplog.at_level(logging.WARNING):
            config = _build(_default_instance())
        # auth_login doesn't support idor_basic → skip, no exception
        auth_ep = config.get_endpoint("auth_login")
        assert auth_ep.flaw is None


@pytest.fixture
def tmp_registry():
    """A minimal registry + instance config that attempts an incompatible user flaw override."""
    reg = CatalogRegistry()
    reg.register_response_profile(ResponseProfileDefinition(
        id="rp", name="RP", difficulty=Difficulty.MEDIUM,
    ))
    reg.register_flaw_profile(SecurityFlawProfileDefinition(
        id="idor_basic", name="IDOR", kind=FlawKind.IDOR,
        compatible_operation_types=(OperationType.OBJECT_READ,),
    ))
    reg.register_endpoint(EndpointDefinition(
        id="recon_ep", method=HttpMethod.GET, path_pattern="/.env",
        operation_type=OperationType.RECON,           # NOT OBJECT_READ
        surface_type=SurfaceType.RECON,
        resource_type=ResourceType.CONFIG,
        sensitivity_level=SensitivityLevel.CRITICAL,
        default_response_profile_id="rp",
        supported_flaw_profile_ids=(),               # idor_basic not supported
    ))
    reg.register_group(EndpointGroupDefinition(
        id="grp", name="G", endpoint_ids=("recon_ep",),
    ))
    reg.register_template(BaseTemplateDefinition(
        id="tmpl", name="T",
        endpoint_group_ids=("grp",),
        default_response_profile_id="rp",
        compatible_extension_ids=(),
    ))
    reg.validate_all()
    instance = InstanceConfig(
        base_template_id="tmpl",
        endpoint_configs={
            "recon_ep": EndpointConfig(
                endpoint_id="recon_ep",
                flaw_profile_id="idor_basic",   # incompatible: not in supported list
            )
        },
    )
    return reg, instance


# ── Extensions ────────────────────────────────────────────────────────────────

class TestExtensions:
    def test_extension_adds_endpoints(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            enabled_extension_ids=["file_server_ext"],
        )
        config = _build(instance)
        assert config.get_endpoint("files_upload") is not None
        assert config.get_endpoint("files_download") is not None

    def test_extension_endpoint_has_correct_provenance(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            enabled_extension_ids=["file_server_ext"],
        )
        config = _build(instance)
        ep = config.get_endpoint("files_upload")
        assert ep is not None
        assert "file_server_ext" in ep.extension_ids

    def test_template_endpoint_has_empty_extension_ids(self):
        config = _build(_default_instance())
        ep = config.get_endpoint("orders_get")
        assert ep is not None
        assert ep.extension_ids == ()

    def test_unknown_extension_raises(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            enabled_extension_ids=["nonexistent_ext"],
        )
        with pytest.raises(BuildError, match="not found in catalog"):
            _build(instance)

    def test_extension_incompatible_with_template_raises(self):
        """Use corporate_saas template which also supports both extensions.
        Inject a fake incompatible scenario via a minimal registry."""
        reg = CatalogRegistry()
        reg.register_response_profile(ResponseProfileDefinition(
            id="rp", name="RP", difficulty=Difficulty.MEDIUM,
        ))
        reg.register_extension(ExtensionPackDefinition(
            id="ext_a", name="A",
        ))
        reg.register_extension(ExtensionPackDefinition(
            id="ext_b", name="B", incompatible_with=("ext_a",),
        ))
        reg.register_template(BaseTemplateDefinition(
            id="tmpl", name="T",
            default_response_profile_id="rp",
            compatible_extension_ids=("ext_a", "ext_b"),
        ))
        reg.validate_all()
        instance = InstanceConfig(
            base_template_id="tmpl",
            enabled_extension_ids=["ext_a", "ext_b"],
        )
        with pytest.raises(BuildError, match="mutually incompatible"):
            build_effective_runtime_config(instance, reg)

    def test_extension_not_compatible_with_template_raises(self):
        instance = InstanceConfig(
            base_template_id="corporate_saas",
            enabled_extension_ids=["file_server_ext"],
        )
        # corporate_saas has file_server_ext in compatible list, so this is fine
        # Let's use a minimal registry where it's NOT listed
        reg = CatalogRegistry()
        reg.register_response_profile(ResponseProfileDefinition(
            id="rp", name="RP", difficulty=Difficulty.MEDIUM,
        ))
        reg.register_extension(ExtensionPackDefinition(id="ext_a", name="A"))
        reg.register_template(BaseTemplateDefinition(
            id="tmpl", name="T",
            default_response_profile_id="rp",
            compatible_extension_ids=(),   # ext_a NOT listed
        ))
        reg.validate_all()
        instance2 = InstanceConfig(
            base_template_id="tmpl",
            enabled_extension_ids=["ext_a"],
        )
        with pytest.raises(BuildError, match="not listed as compatible"):
            build_effective_runtime_config(instance2, reg)

    def test_unknown_template_raises(self):
        instance = InstanceConfig(base_template_id="ghost_template")
        with pytest.raises(BuildError, match="not found in catalog"):
            _build(instance)


# ── Runtime config lookups ────────────────────────────────────────────────────

class TestRuntimeLookups:
    def test_get_endpoint_by_path(self):
        config = _build(_default_instance())
        ep = config.get_endpoint_by_path("GET", "/api/v1/orders/{order_id}")
        assert ep is not None
        assert ep.endpoint_id == "orders_get"

    def test_get_endpoint_by_path_wrong_method_returns_none(self):
        config = _build(_default_instance())
        ep = config.get_endpoint_by_path("DELETE", "/api/v1/orders/{order_id}")
        assert ep is None

    def test_enabled_endpoints_filters_disabled(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "recon_env": EndpointConfig(endpoint_id="recon_env", enabled=False),
            },
        )
        config = _build(instance)
        enabled_ids = [ep.endpoint_id for ep in config.enabled_endpoints()]
        assert "recon_env" not in enabled_ids
        assert "orders_get" in enabled_ids


# ── InteractionContext ────────────────────────────────────────────────────────

class TestInteractionContext:
    def test_to_extra_json_fragment_has_required_keys(self):
        ctx = InteractionContext(
            endpoint_id="orders_get",
            operation_type=OperationType.OBJECT_READ,
            surface_type=SurfaceType.PUBLIC_API,
            resource_type=ResourceType.ORDER,
            sensitivity_level=SensitivityLevel.MEDIUM,
            template_id="ecommerce",
            extension_ids=(),
            triggered_flaws=("idor_basic",),
            outcome=InteractionOutcome(status_code=200, response_bytes=512, latency_ms=45),
        )
        fragment = ctx.to_extra_json_fragment()
        for key in ("endpoint_id", "operation_type", "surface_type", "resource_type",
                    "template_id", "extension_ids", "triggered_flaws"):
            assert key in fragment, f"Missing key: {key}"

    def test_fragment_values_are_strings_not_enums(self):
        ctx = InteractionContext(
            endpoint_id="auth_login",
            operation_type=OperationType.AUTH_LOGIN,
            surface_type=SurfaceType.PUBLIC_API,
            resource_type=ResourceType.CREDENTIAL,
            sensitivity_level=SensitivityLevel.MEDIUM,
            template_id="ecommerce",
            extension_ids=(),
            triggered_flaws=(),
            outcome=InteractionOutcome(status_code=200, response_bytes=128, latency_ms=10),
        )
        fragment = ctx.to_extra_json_fragment()
        # Values must be plain strings (for JSON serialisation), not enum instances
        assert isinstance(fragment["operation_type"], str)
        assert isinstance(fragment["surface_type"], str)
        assert isinstance(fragment["resource_type"], str)

    def test_from_effective_endpoint_factory(self):
        ctx = InteractionContext.from_effective_endpoint(
            endpoint_id="orders_get",
            operation_type=OperationType.OBJECT_READ,
            surface_type=SurfaceType.PUBLIC_API,
            resource_type=ResourceType.ORDER,
            sensitivity_level=SensitivityLevel.MEDIUM,
            template_id="ecommerce",
            extension_ids=(),
            triggered_flaws=("idor_basic",),
            outcome=InteractionOutcome(status_code=200, response_bytes=256, latency_ms=30),
        )
        assert ctx.endpoint_id == "orders_get"
        assert ctx.triggered_flaws == ("idor_basic",)


# ── InstanceConfig validation ─────────────────────────────────────────────────

class TestInstanceConfigValidation:
    def test_empty_template_id_raises(self):
        with pytest.raises(ValueError):
            InstanceConfig(base_template_id="")

    def test_endpoint_config_key_mismatch_raises(self):
        """endpoint_configs key must match EndpointConfig.endpoint_id."""
        with pytest.raises(ValueError, match="does not match"):
            InstanceConfig(
                base_template_id="ecommerce",
                endpoint_configs={
                    "wrong_key": EndpointConfig(endpoint_id="orders_get"),
                },
            )

    def test_fixed_status_out_of_range_raises(self):
        with pytest.raises(ValueError):
            EndpointConfig(endpoint_id="ep", fixed_status=99)

    def test_negative_latency_raises(self):
        with pytest.raises(ValueError):
            EndpointConfig(endpoint_id="ep", latency_ms=-1)

    def test_flaw_explicitly_disabled_property(self):
        cfg = EndpointConfig(endpoint_id="ep", flaw_profile_id="")
        assert cfg.flaw_explicitly_disabled is True

    def test_flaw_none_not_explicitly_disabled(self):
        cfg = EndpointConfig(endpoint_id="ep", flaw_profile_id=None)
        assert cfg.flaw_explicitly_disabled is False

    def test_serialise_roundtrip(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            enabled_extension_ids=["file_server_ext"],
            mutation_config=MutationConfig(policy="daily", intensity=2),
            response_rules=[
                ResponseRule(
                    id="rule_orders",
                    match=ResponseRuleMatch(endpoint_group_id="orders"),
                    action=ResponseRuleAction(extra_latency_ms=80),
                )
            ],
            endpoint_configs={
                "orders_get": EndpointConfig(
                    endpoint_id="orders_get",
                    flaw_profile_id="idor_advanced",
                    fixed_status=200,
                )
            },
        )
        json_str = instance.to_json()
        restored = InstanceConfig.from_json(json_str)
        assert restored.base_template_id == "ecommerce"
        assert restored.enabled_extension_ids == ["file_server_ext"]
        assert restored.endpoint_configs["orders_get"].flaw_profile_id == "idor_advanced"
        assert restored.mutation_config.policy == "daily"
        assert restored.response_rules[0].id == "rule_orders"
