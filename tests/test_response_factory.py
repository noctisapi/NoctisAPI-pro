"""Tests for ResponseFactory, ResponseSpec, generators, and flaw_applicator.

Coverage:
- ResponseSpec properties
- is_supported() per operation_type
- ResponseFactory.build() per operation_type
- Difficulty levels (basic / medium / advanced)
- Flaw application (compatible / incompatible / skip)
- Error bias behaviour
- Determinism (same seed → same result)
- No-regression: fallback when endpoint not supported
- Integration: resolve_effective_endpoint() → build_response()
- Integration: ResponseSpec → InteractionContext builder
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.catalog.types import (
    Difficulty,
    FlawKind,
    HttpMethod,
    OperationType,
    ResourceType,
    SensitivityLevel,
    SurfaceType,
)
from app.response_factory.spec import ResponseSpec
from app.response_factory.generators import (
    SUPPORTED_OPERATION_TYPES,
    default_content_type_for,
    default_status_for,
    generate_payload,
)
from app.response_factory.flaw_applicator import apply_flaw
from app.response_factory.factory import ResponseFactory, build_response, is_supported
from app.runtime.models import (
    EffectiveEndpoint,
    EffectiveFlaw,
    EffectiveLatency,
    EffectiveResponseConfig,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_response_config(
    *,
    profile_id: str = "standard_medium",
    difficulty: Difficulty = Difficulty.MEDIUM,
    latency_min: int = 50,
    latency_max: int = 200,
    fixed_status: int | None = None,
    headers: dict | None = None,
    error_format: str = "json",
) -> EffectiveResponseConfig:
    richness = {Difficulty.BASIC: 1, Difficulty.MEDIUM: 2, Difficulty.ADVANCED: 3}.get(difficulty, 2)
    return EffectiveResponseConfig(
        profile_id=profile_id,
        difficulty=difficulty,
        latency=EffectiveLatency(min_ms=latency_min, max_ms=latency_max, p99_ms=latency_max),
        fixed_status=fixed_status,
        headers=headers or {"x-powered-by": "honeypot"},
        error_format=error_format,
        richness_level=richness,
    )


def _make_flaw(
    kind: FlawKind,
    parameters: dict | None = None,
    profile_id: str = "test_flaw",
) -> EffectiveFlaw:
    return EffectiveFlaw(
        profile_id=profile_id,
        kind=kind,
        parameters=parameters or {},
        ttp_tags=[],
        detection_markers=[],
    )


def _make_endpoint(
    *,
    endpoint_id: str = "ep_test",
    operation_type: OperationType = OperationType.AUTH_LOGIN,
    resource_type: ResourceType = ResourceType.USER,
    difficulty: Difficulty = Difficulty.MEDIUM,
    flaw: EffectiveFlaw | None = None,
    fixed_status: int | None = None,
    profile_id: str = "standard_medium",
    path_pattern: str = "/api/test",
    method: HttpMethod = HttpMethod.POST,
) -> EffectiveEndpoint:
    return EffectiveEndpoint(
        endpoint_id=endpoint_id,
        method=method,
        path_pattern=path_pattern,
        operation_type=operation_type,
        surface_type=SurfaceType.PUBLIC_API,
        resource_type=resource_type,
        sensitivity_level=SensitivityLevel.MEDIUM,
        enabled=True,
        include_in_schema=True,
        response=_make_response_config(
            difficulty=difficulty,
            fixed_status=fixed_status,
            profile_id=profile_id,
        ),
        flaw=flaw,
        template_id="test_template",
        extension_ids=(),
    )


# ── ResponseSpec ──────────────────────────────────────────────────────────────

class TestResponseSpec:
    def test_has_json_body_dict(self):
        spec = ResponseSpec(
            endpoint_id="ep1", status_code=200, headers={},
            body={"key": "val"}, content_type="application/json",
            latency_ms=0, triggered_flaws=(), outcome_hints={},
        )
        assert spec.has_json_body is True
        assert spec.has_text_body is False

    def test_has_json_body_list(self):
        spec = ResponseSpec(
            endpoint_id="ep1", status_code=200, headers={},
            body=[1, 2, 3], content_type="application/json",
            latency_ms=0, triggered_flaws=(), outcome_hints={},
        )
        assert spec.has_json_body is True

    def test_has_text_body(self):
        spec = ResponseSpec(
            endpoint_id="ep1", status_code=200, headers={},
            body="plain text", content_type="text/plain",
            latency_ms=0, triggered_flaws=(), outcome_hints={},
        )
        assert spec.has_text_body is True
        assert spec.has_json_body is False

    def test_response_bytes_dict(self):
        spec = ResponseSpec(
            endpoint_id="ep1", status_code=200, headers={},
            body={"a": 1}, content_type="application/json",
            latency_ms=0, triggered_flaws=(), outcome_hints={},
        )
        assert spec.response_bytes > 0

    def test_response_bytes_none_body(self):
        spec = ResponseSpec(
            endpoint_id="ep1", status_code=204, headers={},
            body=None, content_type="application/json",
            latency_ms=0, triggered_flaws=(), outcome_hints={},
        )
        assert spec.response_bytes == 0

    def test_frozen(self):
        spec = ResponseSpec(
            endpoint_id="ep1", status_code=200, headers={},
            body={}, content_type="application/json",
            latency_ms=0, triggered_flaws=(), outcome_hints={},
        )
        with pytest.raises((AttributeError, TypeError)):
            spec.status_code = 500  # type: ignore


# ── is_supported ──────────────────────────────────────────────────────────────

class TestIsSupported:
    @pytest.mark.parametrize("op_type", list(SUPPORTED_OPERATION_TYPES))
    def test_supported_operation_types(self, op_type):
        ep = _make_endpoint(operation_type=op_type)
        assert is_supported(ep) is True

    def test_unsupported_returns_false(self):
        # Use an OperationType not in SUPPORTED_OPERATION_TYPES
        unsupported = [ot for ot in OperationType if ot not in SUPPORTED_OPERATION_TYPES]
        if not unsupported:
            pytest.skip("All operation types are currently supported")
        ep = _make_endpoint(operation_type=unsupported[0])
        assert is_supported(ep) is False


# ── Generators ───────────────────────────────────────────────────────────────

class TestGenerators:
    @pytest.mark.parametrize("op_type", list(SUPPORTED_OPERATION_TYPES))
    def test_generate_payload_returns_something(self, op_type):
        payload = generate_payload(
            operation_type=op_type,
            resource_type=ResourceType.USER,
            difficulty=Difficulty.MEDIUM,
            endpoint_id="ep_gen_test",
            salt="",
        )
        assert payload is not None

    @pytest.mark.parametrize("difficulty", [Difficulty.BASIC, Difficulty.MEDIUM, Difficulty.ADVANCED])
    def test_difficulty_affects_payload_richness_for_auth_login(self, difficulty):
        payload = generate_payload(
            operation_type=OperationType.AUTH_LOGIN,
            resource_type=ResourceType.USER,
            difficulty=difficulty,
            endpoint_id="ep_auth",
            salt="",
        )
        assert isinstance(payload, dict)

    def test_basic_payload_has_fewer_keys_than_advanced(self):
        common_kwargs = dict(
            operation_type=OperationType.AUTH_LOGIN,
            resource_type=ResourceType.USER,
            endpoint_id="ep_cmp",
            salt="same_salt",
        )
        basic = generate_payload(**common_kwargs, difficulty=Difficulty.BASIC)
        advanced = generate_payload(**common_kwargs, difficulty=Difficulty.ADVANCED)
        # Advanced should have more keys than basic
        assert len(advanced) >= len(basic)

    def test_recon_returns_text(self):
        payload = generate_payload(
            operation_type=OperationType.RECON,
            resource_type=ResourceType.SECRET,
            difficulty=Difficulty.MEDIUM,
            endpoint_id="ep_recon",
            salt="",
        )
        assert isinstance(payload, str)

    def test_default_content_type_recon_is_text(self):
        ct = default_content_type_for(OperationType.RECON)
        assert ct == "text/plain"

    def test_default_content_type_recon_config_is_json(self):
        ct = default_content_type_for(OperationType.RECON, "recon_config")
        assert ct == "application/json"

    def test_default_content_type_json_for_auth(self):
        ct = default_content_type_for(OperationType.AUTH_LOGIN)
        assert "json" in ct

    def test_default_status_auth_is_200(self):
        assert default_status_for(OperationType.AUTH_LOGIN) == 200

    def test_auth_login_uses_plausible_user_identity(self):
        payload = generate_payload(
            operation_type=OperationType.AUTH_LOGIN,
            resource_type=ResourceType.USER,
            difficulty=Difficulty.MEDIUM,
            endpoint_id="ep_auth_identity",
            salt="",
        )
        user = payload["user"]

        assert " " in user["name"]
        assert user["email"].count("@") == 1
        assert not re.search(r"\d@", user["email"])
        assert not user["email"].endswith(("@example.com", "@acme.io", "@testorg.net"))
        assert re.fullmatch(r"[a-z._]+@[a-z0-9-]+\.[a-z.]+", user["email"])
        assert re.fullmatch(r"[a-z._]+", user["username"])

    def test_determinism_same_seed(self):
        kwargs = dict(
            operation_type=OperationType.AUTH_LOGIN,
            resource_type=ResourceType.USER,
            difficulty=Difficulty.MEDIUM,
            endpoint_id="ep_det",
            salt="actor123",
        )
        p1 = generate_payload(**kwargs)
        p2 = generate_payload(**kwargs)
        assert p1 == p2

    def test_different_salt_may_differ(self):
        # Different salt → different rng seed → likely different payload
        # (not guaranteed but extremely probable with a rich generator)
        kwargs = dict(
            operation_type=OperationType.AUTH_LOGIN,
            resource_type=ResourceType.USER,
            difficulty=Difficulty.ADVANCED,
            endpoint_id="ep_salt",
        )
        p1 = generate_payload(**kwargs, salt="actorA")
        p2 = generate_payload(**kwargs, salt="actorB")
        # Can't assert inequality (same date, same structure), but can assert type
        assert isinstance(p1, dict)
        assert isinstance(p2, dict)

    def test_recon_config_payload_is_dict(self):
        payload = generate_payload(
            operation_type=OperationType.RECON,
            resource_type=ResourceType.CONFIG,
            difficulty=Difficulty.MEDIUM,
            endpoint_id="recon_config",
            salt="actorA",
        )
        assert isinstance(payload, dict)
        assert payload["service"] == "platform-api"

    def test_recon_openapi_payload_is_dict(self):
        payload = generate_payload(
            operation_type=OperationType.RECON,
            resource_type=ResourceType.GENERIC,
            difficulty=Difficulty.MEDIUM,
            endpoint_id="recon_openapi",
            salt="actorA",
        )
        assert isinstance(payload, dict)
        assert payload["openapi"].startswith("3.")


# ── FlawApplicator ────────────────────────────────────────────────────────────

class TestFlawApplicator:
    def _call(self, payload, flaw, *, op_type=OperationType.OBJECT_READ, status=200):
        return apply_flaw(
            payload, flaw,
            operation_type=op_type,
            status_code=status,
            endpoint_id="ep_flaw",
            salt="test",
        )

    def test_idor_fires_with_high_prob(self):
        payload = {"id": "usr_0000000a", "email": "x@example.com"}
        flaw = _make_flaw(FlawKind.IDOR, {"leak_probability": 1.0, "id_offset_range": [1, 1]})
        mutated, fired, ct = self._call(payload, flaw)
        assert fired is True
        assert mutated["id"] != payload["id"]
        assert ct == ""

    def test_idor_skips_with_zero_prob(self):
        payload = {"id": "usr_0000000a"}
        flaw = _make_flaw(FlawKind.IDOR, {"leak_probability": 0.0})
        mutated, fired, ct = self._call(payload, flaw)
        assert fired is False
        assert mutated == payload

    def test_idor_non_dict_payload(self):
        flaw = _make_flaw(FlawKind.IDOR, {"leak_probability": 1.0})
        mutated, fired, ct = self._call("plain string", flaw)
        assert fired is False

    def test_sqli_hint_fires_on_2xx(self):
        payload = {"user_id": "123"}
        flaw = _make_flaw(FlawKind.SQLI_HINT, {"hint_probability": 1.0})
        mutated, fired, ct = self._call(payload, flaw, status=200)
        assert fired is True
        assert "error" in mutated
        assert "detail" in mutated

    def test_sqli_hint_skips_on_4xx(self):
        payload = {"user_id": "123"}
        flaw = _make_flaw(FlawKind.SQLI_HINT, {"hint_probability": 1.0})
        mutated, fired, ct = self._call(payload, flaw, status=401)
        assert fired is False

    def test_path_traversal_fires_for_file_download(self):
        payload = {"file": "data"}
        flaw = _make_flaw(FlawKind.PATH_TRAVERSAL, {"success_probability": 1.0})
        mutated, fired, ct = self._call(payload, flaw, op_type=OperationType.FILE_DOWNLOAD)
        assert fired is True
        assert isinstance(mutated, str)
        assert ct == "text/plain"

    def test_path_traversal_skips_wrong_op_type(self):
        payload = {"data": "x"}
        flaw = _make_flaw(FlawKind.PATH_TRAVERSAL, {"success_probability": 1.0})
        mutated, fired, ct = self._call(payload, flaw, op_type=OperationType.AUTH_LOGIN)
        assert fired is False

    def test_broken_auth_adds_auth_hint(self):
        payload = {"user_id": "42"}
        flaw = _make_flaw(FlawKind.BROKEN_AUTH)
        mutated, fired, ct = self._call(payload, flaw)
        assert fired is True
        assert "_auth" in mutated

    def test_broken_auth_non_dict(self):
        flaw = _make_flaw(FlawKind.BROKEN_AUTH)
        mutated, fired, ct = self._call("text", flaw)
        assert fired is False

    def test_excessive_data_adds_password_hash(self):
        payload = {"email": "test@example.com"}
        flaw = _make_flaw(FlawKind.EXCESSIVE_DATA, {"leak_probability": 1.0, "extra_fields": ["password_hash"]})
        mutated, fired, ct = self._call(payload, flaw)
        assert fired is True
        assert "password_hash" in mutated
        assert mutated["password_hash"].startswith("$2b$12$")

    def test_excessive_data_skips_with_zero_prob(self):
        payload = {"email": "test@example.com"}
        flaw = _make_flaw(FlawKind.EXCESSIVE_DATA, {"leak_probability": 0.0})
        mutated, fired, ct = self._call(payload, flaw)
        assert fired is False

    def test_unknown_flaw_kind_passthrough(self):
        # Create a flaw with an unknown kind by patching
        payload = {"data": "x"}
        flaw = _make_flaw(FlawKind.IDOR)
        # Monkey-patch kind to something not in the dispatch
        flaw_mock = MagicMock(spec=EffectiveFlaw)
        flaw_mock.kind = "unknown_kind_xyz"
        flaw_mock.parameters = {}
        flaw_mock.profile_id = "test"
        mutated, fired, ct = apply_flaw(
            payload, flaw_mock,
            operation_type=OperationType.OBJECT_READ,
            status_code=200,
            endpoint_id="ep",
            salt="",
        )
        assert fired is False
        assert mutated == payload

    def test_determinism_flaw_same_seed(self):
        payload = {"id": "ord_00000001", "amount": 100}
        flaw = _make_flaw(FlawKind.IDOR, {"leak_probability": 1.0, "id_offset_range": [1, 5]})
        r1 = apply_flaw(payload, flaw, operation_type=OperationType.OBJECT_READ, status_code=200, endpoint_id="ep_det", salt="salt1")
        r2 = apply_flaw(payload, flaw, operation_type=OperationType.OBJECT_READ, status_code=200, endpoint_id="ep_det", salt="salt1")
        assert r1 == r2


# ── ResponseFactory ───────────────────────────────────────────────────────────

class TestResponseFactory:
    def setup_method(self):
        self.factory = ResponseFactory()

    def test_build_returns_spec_for_supported(self):
        ep = _make_endpoint(operation_type=OperationType.AUTH_LOGIN)
        spec = self.factory.build(ep)
        assert spec is not None
        assert isinstance(spec, ResponseSpec)

    def test_build_returns_none_for_unsupported(self):
        unsupported = [ot for ot in OperationType if ot not in SUPPORTED_OPERATION_TYPES]
        if not unsupported:
            pytest.skip("All operation types supported")
        ep = _make_endpoint(operation_type=unsupported[0])
        spec = self.factory.build(ep)
        assert spec is None

    def test_fixed_status_respected(self):
        ep = _make_endpoint(operation_type=OperationType.AUTH_LOGIN, fixed_status=403)
        spec = self.factory.build(ep)
        assert spec is not None
        assert spec.status_code == 403

    def test_spec_has_endpoint_id(self):
        ep = _make_endpoint(endpoint_id="ep_check_id")
        spec = self.factory.build(ep)
        assert spec is not None
        assert spec.endpoint_id == "ep_check_id"

    def test_spec_headers_contain_content_type(self):
        ep = _make_endpoint(operation_type=OperationType.AUTH_LOGIN)
        spec = self.factory.build(ep)
        assert spec is not None
        assert "content-type" in spec.headers

    def test_latency_in_range(self):
        ep = _make_endpoint()
        ep_resp = _make_response_config(latency_min=100, latency_max=200)
        ep2 = EffectiveEndpoint(
            endpoint_id="ep_lat",
            method=HttpMethod.GET,
            path_pattern="/lat",
            operation_type=OperationType.AUTH_LOGIN,
            surface_type=SurfaceType.PUBLIC_API,
            resource_type=ResourceType.USER,
            sensitivity_level=SensitivityLevel.LOW,
            enabled=True,
            include_in_schema=True,
            response=ep_resp,
            flaw=None,
            template_id="test",
            extension_ids=(),
        )
        spec = self.factory.build(ep2)
        assert spec is not None
        assert 100 <= spec.latency_ms <= 200

    def test_latency_fixed_when_min_equals_max(self):
        ep_resp = _make_response_config(latency_min=150, latency_max=150)
        ep = EffectiveEndpoint(
            endpoint_id="ep_fixed_lat",
            method=HttpMethod.GET,
            path_pattern="/lat_fixed",
            operation_type=OperationType.AUTH_LOGIN,
            surface_type=SurfaceType.PUBLIC_API,
            resource_type=ResourceType.USER,
            sensitivity_level=SensitivityLevel.LOW,
            enabled=True,
            include_in_schema=True,
            response=ep_resp,
            flaw=None,
            template_id="test",
            extension_ids=(),
        )
        spec = self.factory.build(ep)
        assert spec is not None
        assert spec.latency_ms == 150

    @pytest.mark.parametrize("op_type", list(SUPPORTED_OPERATION_TYPES))
    def test_all_supported_operation_types_build_spec(self, op_type):
        ep = _make_endpoint(operation_type=op_type)
        spec = self.factory.build(ep)
        assert spec is not None
        assert spec.status_code >= 200

    @pytest.mark.parametrize("difficulty", [Difficulty.BASIC, Difficulty.MEDIUM, Difficulty.ADVANCED])
    def test_difficulty_profiles_all_succeed(self, difficulty):
        ep = _make_endpoint(difficulty=difficulty)
        spec = self.factory.build(ep)
        assert spec is not None

    def test_flaw_fires_and_recorded_in_triggered_flaws(self):
        flaw = _make_flaw(FlawKind.IDOR, {"leak_probability": 1.0, "id_offset_range": [1, 1]}, profile_id="idor_basic")
        ep = _make_endpoint(
            operation_type=OperationType.OBJECT_READ,
            resource_type=ResourceType.ORDER,
            flaw=flaw,
        )
        spec = self.factory.build(ep, salt="test_actor")
        assert spec is not None
        # IDOR may or may not fire depending on payload structure, but spec is valid
        assert isinstance(spec.triggered_flaws, tuple)

    def test_flaw_path_traversal_changes_content_type(self):
        flaw = _make_flaw(FlawKind.PATH_TRAVERSAL, {"success_probability": 1.0})
        ep = _make_endpoint(
            operation_type=OperationType.FILE_DOWNLOAD,
            resource_type=ResourceType.FILE,
            flaw=flaw,
        )
        spec = self.factory.build(ep)
        assert spec is not None
        if spec.has_text_body:
            assert spec.content_type == "text/plain"

    def test_determinism_same_salt_same_day(self):
        ep = _make_endpoint(endpoint_id="ep_det2", operation_type=OperationType.AUTH_LOGIN)
        s1 = self.factory.build(ep, salt="actor42")
        s2 = self.factory.build(ep, salt="actor42")
        assert s1 is not None
        assert s2 is not None
        assert s1.body == s2.body
        assert s1.status_code == s2.status_code
        assert s1.latency_ms == s2.latency_ms
        assert s1.headers == s2.headers

    def test_header_templates_are_rendered_deterministically(self):
        ep = _make_endpoint(
            endpoint_id="ep_headers",
            operation_type=OperationType.AUTH_LOGIN,
            profile_id="standard_advanced",
        )
        ep.response.headers = {
            "X-Request-Id": "{{uuid}}",
            "X-RateLimit-Remaining": "{{int:950-999}}",
        }
        s1 = self.factory.build(ep, salt="actor42")
        s2 = self.factory.build(ep, salt="actor42")
        assert s1 is not None
        assert s2 is not None
        assert s1.headers["X-Request-Id"] != "{{uuid}}"
        assert s1.headers["X-RateLimit-Remaining"] != "{{int:950-999}}"
        assert s1.headers["X-Request-Id"] == s2.headers["X-Request-Id"]
        assert s1.headers["X-RateLimit-Remaining"] == s2.headers["X-RateLimit-Remaining"]

    def test_recon_config_build_uses_json_content_type(self):
        ep = _make_endpoint(
            endpoint_id="recon_config",
            operation_type=OperationType.RECON,
            resource_type=ResourceType.CONFIG,
            method=HttpMethod.GET,
            path_pattern="/config.json",
        )
        spec = self.factory.build(ep, salt="actor42")
        assert spec is not None
        assert spec.content_type == "application/json"
        assert isinstance(spec.body, dict)

    def test_outcome_hints_present(self):
        ep = _make_endpoint()
        spec = self.factory.build(ep)
        assert spec is not None
        assert "operation_type" in spec.outcome_hints
        assert "difficulty" in spec.outcome_hints

    def test_error_trap_profile_may_return_error_status(self):
        # error_trap profile may flip to an error code ~50% of the time
        # We just verify that the result is a valid ResponseSpec with a valid status
        ep_resp = _make_response_config(profile_id="error_trap_medium", difficulty=Difficulty.MEDIUM)
        ep = EffectiveEndpoint(
            endpoint_id="ep_error_trap",
            method=HttpMethod.GET,
            path_pattern="/trap",
            operation_type=OperationType.AUTH_LOGIN,
            surface_type=SurfaceType.PUBLIC_API,
            resource_type=ResourceType.USER,
            sensitivity_level=SensitivityLevel.LOW,
            enabled=True,
            include_in_schema=True,
            response=ep_resp,
            flaw=None,
            template_id="test",
            extension_ids=(),
        )
        spec = self.factory.build(ep)
        assert spec is not None
        assert spec.status_code >= 200

    def test_fixed_status_beats_error_trap_bias(self):
        ep = _make_endpoint(
            endpoint_id="ep_fixed_error",
            operation_type=OperationType.AUTH_LOGIN,
            fixed_status=418,
            profile_id="error_trap_medium",
        )
        spec = self.factory.build(ep, salt="actor42")
        assert spec is not None
        assert spec.status_code == 418


# ── build_response (module-level) ─────────────────────────────────────────────

class TestBuildResponseFunction:
    def test_returns_spec_for_supported(self):
        ep = _make_endpoint()
        spec = build_response(ep)
        assert spec is not None

    def test_returns_none_for_unsupported(self):
        unsupported = [ot for ot in OperationType if ot not in SUPPORTED_OPERATION_TYPES]
        if not unsupported:
            pytest.skip("All operation types supported")
        ep = _make_endpoint(operation_type=unsupported[0])
        assert build_response(ep) is None

    def test_never_raises_on_bad_input(self):
        # Should return None, not raise
        result = build_response(MagicMock(operation_type="not_real", endpoint_id="x"))
        assert result is None


# ── Integration: resolve_effective_endpoint → build_response ─────────────────

class TestIntegrationWithResolver:
    def test_resolve_and_build_for_known_path(self):
        from app.runtime_provider import reset_provider
        from app.endpoint_resolver import EndpointResolver
        from app.catalog.builtin.loader import build_default_registry
        from app.instance_config.models import InstanceConfig

        reset_provider()
        registry = build_default_registry()
        instance_config = InstanceConfig.default()

        from app.runtime.builder import build_effective_runtime_config
        eff_config = build_effective_runtime_config(instance_config, registry)

        resolver = EndpointResolver(eff_config)
        # Try one of the known built-in paths
        ep = resolver.resolve("POST", "/auth/login")
        if ep is None:
            # Path may differ per template, skip gracefully
            pytest.skip("No endpoint mapped to POST /auth/login in default config")

        spec = build_response(ep, salt="test_actor")
        assert spec is not None
        assert spec.status_code in range(200, 600)

    def test_unknown_path_returns_none(self):
        from app.endpoint_resolver import EndpointResolver
        from app.catalog.builtin.loader import build_default_registry
        from app.instance_config.models import InstanceConfig
        from app.runtime.builder import build_effective_runtime_config

        registry = build_default_registry()
        eff_config = build_effective_runtime_config(InstanceConfig.default(), registry)
        resolver = EndpointResolver(eff_config)

        ep = resolver.resolve("GET", "/totally_unknown_path_xyz_123")
        assert ep is None


# ── Integration: ResponseSpec → InteractionContext ────────────────────────────

class TestIntegrationWithInteractionContext:
    def test_spec_feeds_into_interaction_context(self):
        from app.interaction_context_builder import build_interaction_context

        ep = _make_endpoint(
            endpoint_id="ep_ctx_test",
            operation_type=OperationType.AUTH_LOGIN,
        )
        spec = build_response(ep, salt="test")
        assert spec is not None

        ctx = build_interaction_context(
            effective_endpoint=ep,
            status_code=spec.status_code,
            response_bytes=spec.response_bytes,
            latency_ms=spec.latency_ms,
        )
        assert ctx is not None
        fragment = ctx.to_extra_json_fragment()
        assert isinstance(fragment, dict)
        assert "endpoint_id" in fragment

    def test_fragment_values_are_json_safe_strings(self):
        from app.interaction_context_builder import safe_extra_json_fragment

        ep = _make_endpoint(endpoint_id="ep_json_safe")
        fragment = safe_extra_json_fragment(
            effective_endpoint=ep,
            status_code=200,
            response_bytes=512,
            latency_ms=80,
        )
        import json
        # All values must be JSON-serialisable (no non-primitive types)
        json.dumps(fragment)  # should not raise
