"""Tests for EndpointResolver: path matching, pattern matching, edge cases.

No DB, no filesystem. All tests use in-memory catalog via build_default_registry().
"""
import pytest

from app.catalog.builtin.loader import build_default_registry
from app.endpoint_resolver import (
    EndpointResolver,
    _pattern_matches,
    _specificity_score,
)
from app.instance_config.models import EndpointConfig, InstanceConfig
from app.runtime.builder import build_effective_runtime_config
from app.runtime_provider import RuntimeConfigProvider


# ── Fixtures ──────────────────────────────────────────────────────────────────

class _StaticProvider:
    """Provider backed by a fixed EffectiveRuntimeConfig — no DB, no cache."""

    def __init__(self, instance_config: InstanceConfig | None = None) -> None:
        registry = build_default_registry()
        cfg = instance_config or InstanceConfig.default()
        self._config = build_effective_runtime_config(cfg, registry)

    def get_config(self):
        return self._config


def _resolver(instance_config: InstanceConfig | None = None) -> EndpointResolver:
    return EndpointResolver(_StaticProvider(instance_config))


# ── _pattern_matches ──────────────────────────────────────────────────────────

class TestPatternMatches:
    def test_exact_literal_match(self):
        assert _pattern_matches("/auth/login", "/auth/login") is True

    def test_exact_literal_no_match(self):
        assert _pattern_matches("/auth/login", "/auth/logout") is False

    def test_single_param_match(self):
        assert _pattern_matches("/api/v1/orders/{id}", "/api/v1/orders/123") is True

    def test_single_param_no_match_different_depth(self):
        assert _pattern_matches("/api/v1/orders/{id}", "/api/v1/orders/123/items") is False

    def test_multiple_params_match(self):
        assert _pattern_matches("/api/{v}/orders/{id}", "/api/v1/orders/42") is True

    def test_trailing_slash_normalised(self):
        assert _pattern_matches("/auth/login/", "/auth/login") is True
        assert _pattern_matches("/auth/login", "/auth/login/") is True

    def test_root_path(self):
        assert _pattern_matches("/", "/") is True

    def test_single_segment(self):
        assert _pattern_matches("/.env", "/.env") is True

    def test_param_does_not_match_empty_segment(self):
        # "/api/v1/orders//" has an empty segment after split — param needs non-empty
        # Actually split("//") → ["", "", ""]... depends on input.
        # Let's just test normal paths:
        assert _pattern_matches("/api/v1/orders/{id}", "/api/v1/orders/") is False

    def test_literal_segment_case_sensitive(self):
        assert _pattern_matches("/AUTH/login", "/auth/login") is False


class TestSpecificityScore:
    def test_all_literal(self):
        assert _specificity_score("/api/v1/orders") == 4  # "", "api", "v1", "orders"

    def test_one_param(self):
        # /api/v1/orders/{id} → "", "api", "v1", "orders" = 4 literal, 1 param
        assert _specificity_score("/api/v1/orders/{id}") == 4

    def test_all_params(self):
        assert _specificity_score("/{a}/{b}/{c}") == 1  # only the "" before first /

    def test_root(self):
        assert _specificity_score("/") == 2  # "", ""


# ── EndpointResolver.resolve ──────────────────────────────────────────────────

class TestEndpointResolverResolve:
    def test_exact_path_match(self):
        ep = _resolver().resolve("POST", "/auth/login")
        assert ep is not None
        assert ep.endpoint_id == "auth_login"

    def test_exact_path_match_recon(self):
        ep = _resolver().resolve("GET", "/.env")
        assert ep is not None
        assert ep.endpoint_id == "recon_env"

    def test_parameterised_path_match(self):
        ep = _resolver().resolve("GET", "/api/v1/orders/42")
        assert ep is not None
        assert ep.endpoint_id == "orders_get"

    def test_parameterised_user_path(self):
        ep = _resolver().resolve("GET", "/api/v1/users/99")
        assert ep is not None
        assert ep.endpoint_id == "users_get"

    def test_unknown_path_returns_none(self):
        ep = _resolver().resolve("GET", "/this/path/does/not/exist")
        assert ep is None

    def test_wrong_method_returns_none(self):
        """GET /auth/login exists but DELETE /auth/login does not."""
        ep = _resolver().resolve("DELETE", "/auth/login")
        assert ep is None

    def test_method_case_insensitive(self):
        ep = _resolver().resolve("get", "/api/v1/orders/42")
        assert ep is not None
        assert ep.endpoint_id == "orders_get"

    def test_disabled_endpoint_returns_none(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(endpoint_id="orders_get", enabled=False)
            },
        )
        ep = _resolver(instance).resolve("GET", "/api/v1/orders/42")
        assert ep is None

    def test_resolve_including_disabled_returns_disabled(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": EndpointConfig(endpoint_id="orders_get", enabled=False)
            },
        )
        resolver = _resolver(instance)
        ep = resolver.resolve_including_disabled("GET", "/api/v1/orders/42")
        assert ep is not None
        assert ep.enabled is False

    def test_resolver_never_raises_on_bad_path(self):
        resolver = _resolver()
        for bad_path in ("", "no-slash", "//double", "/a/../b", "/../../../etc/passwd"):
            ep = resolver.resolve("GET", bad_path)
            # Must not raise; may return None or a match
            assert ep is None or ep.endpoint_id

    def test_specificity_selects_more_specific_pattern(self):
        """If both /backup/list and /backup/{id} existed, /backup/list should win for /backup/list."""
        # In our catalog, /backup/list and /backup/download/{backup_id} exist.
        # Request to /backup/list should resolve to backup_list (exact), not backup_download.
        ep = _resolver().resolve("GET", "/backup/list")
        assert ep is not None
        assert ep.endpoint_id == "backup_list"

    def test_parameterised_backup_download(self):
        ep = _resolver().resolve("GET", "/backup/download/abc-123")
        assert ep is not None
        assert ep.endpoint_id == "backup_download"


# ── EndpointResolver with extensions ────────────────────────────────────────

class TestResolverWithExtensions:
    def test_extension_endpoint_resolved(self):
        instance = InstanceConfig(
            base_template_id="ecommerce",
            enabled_extension_ids=["file_server_ext"],
        )
        ep = _resolver(instance).resolve("POST", "/files")
        assert ep is not None
        assert ep.endpoint_id == "files_upload"

    def test_extension_endpoint_not_resolved_when_disabled(self):
        """Without file_server_ext enabled, /files should not resolve."""
        ep = _resolver().resolve("POST", "/files")
        assert ep is None


# ── resolve_all / coverage_report ─────────────────────────────────────────────

class TestBulkMethods:
    def test_resolve_all_returns_all_endpoints(self):
        resolver = _resolver()
        all_eps = resolver.resolve_all()
        assert len(all_eps) > 0
        ep_ids = [ep.endpoint_id for ep in all_eps]
        assert "auth_login" in ep_ids
        assert "orders_get" in ep_ids

    def test_coverage_report_structure(self):
        resolver = _resolver()
        report = resolver.coverage_report([
            ("POST", "/auth/login"),
            ("GET", "/api/v1/orders/42"),
            ("GET", "/unknown/path"),
        ])
        assert len(report) == 3
        assert report[0]["endpoint_id"] == "auth_login"
        assert report[1]["endpoint_id"] == "orders_get"
        assert report[2]["endpoint_id"] is None

    def test_coverage_report_has_operation_type(self):
        resolver = _resolver()
        report = resolver.coverage_report([("POST", "/auth/login")])
        assert report[0]["operation_type"] == "auth_login"
