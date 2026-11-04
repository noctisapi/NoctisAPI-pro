"""Tests for InteractionContextBuilder and safe_extra_json_fragment.

Validates:
  - Context construction from EffectiveEndpoint + outcome
  - Flaw trigger detection heuristics
  - safe_extra_json_fragment never raises
  - extra_json fragment has correct types and keys
  - Behaviour when effective_endpoint is None
"""
import pytest

from app.catalog.builtin.loader import build_default_registry
from app.instance_config.models import EndpointConfig, InstanceConfig
from app.interaction_context_builder import (
    InteractionContextBuilder,
    build_interaction_context,
    safe_extra_json_fragment,
)
from app.runtime.builder import build_effective_runtime_config
from app.runtime.context import InteractionContext, InteractionOutcome
from app.runtime.models import EffectiveEndpoint


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def registry():
    return build_default_registry()


def _get_ep(endpoint_id: str, instance: InstanceConfig | None = None) -> EffectiveEndpoint:
    registry = build_default_registry()
    cfg = instance or InstanceConfig.default()
    config = build_effective_runtime_config(cfg, registry)
    ep = config.get_endpoint(endpoint_id)
    assert ep is not None, f"Endpoint '{endpoint_id}' not found"
    return ep


def _ep_with_flaw(endpoint_id: str, flaw_id: str) -> EffectiveEndpoint:
    instance = InstanceConfig(
        base_template_id="ecommerce",
        endpoint_configs={
            endpoint_id: EndpointConfig(
                endpoint_id=endpoint_id,
                flaw_profile_id=flaw_id,
            )
        },
    )
    return _get_ep(endpoint_id, instance)


def _ep_no_flaw(endpoint_id: str) -> EffectiveEndpoint:
    instance = InstanceConfig(
        base_template_id="ecommerce",
        endpoint_configs={
            endpoint_id: EndpointConfig(
                endpoint_id=endpoint_id,
                flaw_profile_id="",  # explicitly disabled
            )
        },
    )
    return _get_ep(endpoint_id, instance)


# ── InteractionContextBuilder.build ──────────────────────────────────────────

class TestContextBuilder:
    def test_basic_build(self):
        ep = _get_ep("orders_get")
        builder = InteractionContextBuilder()
        ctx = builder.build(
            effective_endpoint=ep,
            status_code=200,
            response_bytes=512,
            latency_ms=45,
        )
        assert isinstance(ctx, InteractionContext)
        assert ctx.endpoint_id == "orders_get"
        assert ctx.outcome.status_code == 200
        assert ctx.outcome.response_bytes == 512
        assert ctx.outcome.latency_ms == 45

    def test_operation_type_carried(self):
        ep = _get_ep("orders_get")
        builder = InteractionContextBuilder()
        ctx = builder.build(effective_endpoint=ep, status_code=200)
        from app.catalog.types import OperationType
        assert ctx.operation_type == OperationType.OBJECT_READ

    def test_surface_type_carried(self):
        ep = _get_ep("admin_home")
        builder = InteractionContextBuilder()
        ctx = builder.build(effective_endpoint=ep, status_code=200)
        from app.catalog.types import SurfaceType
        assert ctx.surface_type == SurfaceType.ADMIN

    def test_template_id_carried(self):
        ep = _get_ep("orders_get")
        builder = InteractionContextBuilder()
        ctx = builder.build(effective_endpoint=ep, status_code=200)
        assert ctx.template_id == "ecommerce"


# ── Flaw trigger detection ────────────────────────────────────────────────────

class TestFlawTriggerDetection:
    def test_endpoint_with_flaw_200_triggers_flaw(self):
        ep = _ep_with_flaw("orders_get", "idor_basic")
        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=200,
        )
        assert ctx is not None
        assert ctx.triggered_flaws == ("idor_basic",)
        assert ctx.outcome.flaw_triggered is True

    def test_endpoint_with_flaw_500_does_not_trigger(self):
        """Server errors: flaw was not executed (conservative heuristic)."""
        ep = _ep_with_flaw("orders_get", "idor_basic")
        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=500,
        )
        assert ctx is not None
        assert ctx.triggered_flaws == ()
        assert ctx.outcome.flaw_triggered is False

    def test_endpoint_with_flaw_404_triggers(self):
        """404 < 500 → flaw still considered active."""
        ep = _ep_with_flaw("orders_get", "idor_basic")
        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=404,
        )
        assert ctx is not None
        assert ctx.triggered_flaws == ("idor_basic",)

    def test_endpoint_without_flaw_no_triggered_flaws(self):
        ep = _ep_no_flaw("orders_get")
        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=200,
        )
        assert ctx is not None
        assert ctx.triggered_flaws == ()
        assert ctx.outcome.flaw_triggered is False

    def test_explicit_flaw_override_via_extra_hints(self):
        """Route handler can explicitly set triggered_flaw_ids."""
        ep = _ep_with_flaw("orders_get", "idor_basic")
        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=200,
            extra_hints={"triggered_flaw_ids": ["idor_advanced", "sqli_hint_basic"]},
        )
        assert ctx is not None
        assert set(ctx.triggered_flaws) == {"idor_advanced", "sqli_hint_basic"}

    def test_error_message_carried_from_hints(self):
        ep = _get_ep("recon_env")
        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=500,
            extra_hints={"error": "db connection failed"},
        )
        assert ctx is not None
        assert ctx.outcome.error == "db connection failed"


# ── build_interaction_context (safe version) ─────────────────────────────────

class TestBuildInteractionContext:
    def test_returns_context_on_valid_input(self):
        ep = _get_ep("auth_login")
        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=200,
        )
        assert ctx is not None

    def test_returns_none_on_invalid_inputs(self):
        """Passing garbage should never raise — return None."""
        ctx = build_interaction_context(
            effective_endpoint=None,  # type: ignore
            status_code=200,
        )
        assert ctx is None


# ── safe_extra_json_fragment ──────────────────────────────────────────────────

class TestSafeExtraJsonFragment:
    def test_returns_dict_on_valid_endpoint(self):
        ep = _get_ep("orders_get")
        fragment = safe_extra_json_fragment(
            effective_endpoint=ep,
            status_code=200,
            response_bytes=128,
            latency_ms=30,
        )
        assert isinstance(fragment, dict)
        assert fragment["endpoint_id"] == "orders_get"

    def test_returns_empty_dict_when_endpoint_is_none(self):
        fragment = safe_extra_json_fragment(
            effective_endpoint=None,
            status_code=200,
        )
        assert fragment == {}

    def test_never_raises_for_any_status_code(self):
        ep = _get_ep("orders_get")
        for status in (100, 200, 204, 301, 400, 401, 403, 404, 500, 503):
            fragment = safe_extra_json_fragment(
                effective_endpoint=ep,
                status_code=status,
            )
            assert isinstance(fragment, dict)

    def test_fragment_values_are_json_serialisable(self):
        """All values must be plain Python types (not enums) for JSON serialisation."""
        import json
        ep = _get_ep("backup_download")
        fragment = safe_extra_json_fragment(
            effective_endpoint=ep,
            status_code=200,
        )
        # Must not raise
        json.dumps(fragment)

    def test_fragment_has_required_keys(self):
        ep = _get_ep("auth_login")
        fragment = safe_extra_json_fragment(
            effective_endpoint=ep,
            status_code=200,
        )
        required = {
            "endpoint_id", "operation_type", "surface_type",
            "resource_type", "template_id", "extension_ids", "triggered_flaws",
        }
        assert required.issubset(set(fragment.keys()))

    def test_extension_ids_is_list(self):
        ep = _get_ep("orders_get")
        fragment = safe_extra_json_fragment(effective_endpoint=ep, status_code=200)
        assert isinstance(fragment["extension_ids"], list)

    def test_triggered_flaws_is_list(self):
        ep = _get_ep("orders_get")
        fragment = safe_extra_json_fragment(effective_endpoint=ep, status_code=200)
        assert isinstance(fragment["triggered_flaws"], list)


# ── Integration: resolve → build context ─────────────────────────────────────

class TestResolveAndBuildContext:
    """Simulates what the middleware would do: resolve endpoint, build context."""

    def setup_method(self):
        from app.runtime_provider import reset_provider
        reset_provider()

    def teardown_method(self):
        from app.runtime_provider import reset_provider
        reset_provider()

    def test_full_pipeline_known_endpoint(self):
        from app.runtime_provider import resolve_effective_endpoint

        ep = resolve_effective_endpoint("GET", "/api/v1/orders/42")
        assert ep is not None

        fragment = safe_extra_json_fragment(
            effective_endpoint=ep,
            status_code=200,
            response_bytes=256,
            latency_ms=55,
        )
        assert fragment["endpoint_id"] == "orders_get"
        assert fragment["operation_type"] == "object_read"
        assert fragment["resource_type"] == "order"

    def test_full_pipeline_unknown_path_returns_empty_fragment(self):
        from app.runtime_provider import resolve_effective_endpoint

        ep = resolve_effective_endpoint("GET", "/scanner/probe/unknown")
        assert ep is None

        fragment = safe_extra_json_fragment(
            effective_endpoint=ep,
            status_code=404,
        )
        assert fragment == {}

    def test_full_pipeline_critical_endpoint(self):
        from app.runtime_provider import resolve_effective_endpoint

        ep = resolve_effective_endpoint("GET", "/admin/secrets")
        assert ep is not None

        from app.catalog.types import SensitivityLevel, SurfaceType
        assert ep.sensitivity_level == SensitivityLevel.CRITICAL
        assert ep.surface_type == SurfaceType.INTERNAL

        fragment = safe_extra_json_fragment(
            effective_endpoint=ep,
            status_code=200,
        )
        assert fragment["sensitivity_level"] == "critical"
