"""Tests for LegacyConfigAdapter: mapping api_endpoint_configs → InstanceConfig.

Uses SQLite in-memory DB to replicate the existing DB schema.
"""
import sqlite3
import json
import pytest

from app.catalog.builtin.loader import build_default_registry
from app.catalog.registry import CatalogRegistry
from app.catalog.types import Difficulty
from app.instance_config.models import InstanceConfig
from app.legacy_config_adapter import (
    LegacyConfigAdapter,
    _map_response_profile,
    _find_endpoint_id,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def registry() -> CatalogRegistry:
    return build_default_registry()


def _make_db(rows: list[dict] | None = None) -> sqlite3.Connection:
    """Create an in-memory DB with api_endpoint_configs table."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE api_endpoint_configs (
            method         TEXT NOT NULL DEFAULT '*',
            path           TEXT NOT NULL,
            enabled        INTEGER NOT NULL DEFAULT 1,
            response_mode  TEXT,
            fixed_status   INTEGER,
            richness_level INTEGER NOT NULL DEFAULT 2,
            PRIMARY KEY (method, path)
        )
        """
    )
    if rows:
        for r in rows:
            conn.execute(
                "INSERT INTO api_endpoint_configs "
                "(method, path, enabled, response_mode, fixed_status, richness_level) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    r.get("method", "*"),
                    r["path"],
                    r.get("enabled", 1),
                    r.get("response_mode"),
                    r.get("fixed_status"),
                    r.get("richness_level", 2),
                ),
            )
    conn.commit()
    return conn


def _make_db_with_settings(settings: dict) -> sqlite3.Connection:
    """Create in-memory DB with system_settings table."""
    conn = _make_db()
    conn.execute(
        """
        CREATE TABLE system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
        """
    )
    for k, v in settings.items():
        conn.execute("INSERT INTO system_settings (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    return conn


def _create_legacy_policy_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE api_mutation_settings (
            singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
            mutation_policy TEXT NOT NULL DEFAULT 'none',
            mutation_intensity INTEGER NOT NULL DEFAULT 0,
            updated_ts TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO api_mutation_settings(singleton_id, mutation_policy, mutation_intensity, updated_ts)
        VALUES(1, 'daily', 2, '2026-04-01T00:00:00Z')
        """
    )
    conn.execute(
        """
        CREATE TABLE api_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER NOT NULL DEFAULT 1,
            match_path TEXT,
            match_method TEXT,
            match_user_agent TEXT,
            action_change_richness INTEGER,
            action_force_status INTEGER,
            action_increase_latency INTEGER,
            created_ts TEXT NOT NULL,
            updated_ts TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO api_rules(
            enabled, match_path, match_method, match_user_agent,
            action_change_richness, action_force_status, action_increase_latency,
            created_ts, updated_ts
        ) VALUES(1, '/api/v1/orders', 'GET', 'curl', -1, 429, 60, '2026-04-01T00:00:00Z', '2026-04-01T00:00:00Z')
        """
    )
    conn.commit()


# ── _map_response_profile ─────────────────────────────────────────────────────

class TestMapResponseProfile:
    def test_normal_maps_to_standard_medium(self):
        assert _map_response_profile("normal", 2) == "standard_medium"

    def test_minimal_maps_to_standard_basic(self):
        assert _map_response_profile("minimal", 2) == "standard_basic"

    def test_error_bias_maps_to_error_trap(self):
        assert _map_response_profile("error_bias", 2) == "error_trap_medium"

    def test_richness_3_maps_to_advanced(self):
        assert _map_response_profile(None, 3) == "standard_advanced"

    def test_richness_2_maps_to_medium(self):
        assert _map_response_profile(None, 2) == "standard_medium"

    def test_richness_0_maps_to_basic(self):
        assert _map_response_profile(None, 0) == "standard_basic"

    def test_mode_takes_priority_over_richness(self):
        """response_mode wins when both are set."""
        assert _map_response_profile("minimal", 3) == "standard_basic"

    def test_none_both_returns_none(self):
        assert _map_response_profile(None, None) is None

    def test_unknown_mode_falls_back_to_richness(self):
        assert _map_response_profile("legacy_mode", 3) == "standard_advanced"


# ── _find_endpoint_id ─────────────────────────────────────────────────────────

class TestFindEndpointId:
    def test_exact_match(self, registry):
        ep_id = _find_endpoint_id(registry, "POST", "/auth/login")
        assert ep_id == "auth_login"

    def test_exact_match_case_insensitive_method(self, registry):
        ep_id = _find_endpoint_id(registry, "post", "/auth/login")
        assert ep_id == "auth_login"

    def test_pattern_in_catalog_matches_literal_request(self, registry):
        """Catalog has /api/v1/orders/{order_id}; old DB might store that literally."""
        ep_id = _find_endpoint_id(registry, "GET", "/api/v1/orders/{order_id}")
        assert ep_id == "orders_get"

    def test_no_match_returns_none(self, registry):
        ep_id = _find_endpoint_id(registry, "GET", "/does/not/exist")
        assert ep_id is None

    def test_wildcard_method_finds_get(self, registry):
        ep_id = _find_endpoint_id(registry, "*", "/api/v1/orders/{order_id}")
        assert ep_id == "orders_get"

    def test_wildcard_method_finds_post(self, registry):
        ep_id = _find_endpoint_id(registry, "*", "/api/v1/orders")
        # /api/v1/orders is both GET (orders_list) and POST (orders_create)
        # wildcard tries GET first, so orders_list should be found
        assert ep_id is not None


# ── LegacyConfigAdapter.to_instance_config ───────────────────────────────────

class TestAdapterToInstanceConfig:
    def test_empty_table_returns_default(self, registry):
        conn = _make_db()
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert isinstance(result, InstanceConfig)
        assert result.base_template_id == "ecommerce"
        assert result.endpoint_configs == {}

    def test_no_table_returns_default(self, registry):
        """If api_endpoint_configs doesn't exist yet, should return default."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert isinstance(result, InstanceConfig)

    def test_known_path_mapped_to_endpoint_id(self, registry):
        conn = _make_db([
            {"method": "POST", "path": "/auth/login", "enabled": 1, "response_mode": "normal"},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert "auth_login" in result.endpoint_configs

    def test_enabled_false_preserved(self, registry):
        conn = _make_db([
            {"method": "GET", "path": "/api/v1/orders", "enabled": 0},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert "orders_list" in result.endpoint_configs
        assert result.endpoint_configs["orders_list"].enabled is False

    def test_response_mode_mapped_to_profile(self, registry):
        conn = _make_db([
            {"method": "GET", "path": "/api/v1/orders", "response_mode": "minimal"},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        cfg = result.endpoint_configs.get("orders_list")
        assert cfg is not None
        assert cfg.response_profile_id == "standard_basic"

    def test_richness_3_mapped_to_advanced_profile(self, registry):
        conn = _make_db([
            {"method": "GET", "path": "/api/v1/orders", "richness_level": 3},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        cfg = result.endpoint_configs.get("orders_list")
        assert cfg is not None
        assert cfg.response_profile_id == "standard_advanced"

    def test_fixed_status_preserved(self, registry):
        conn = _make_db([
            {"method": "GET", "path": "/api/v1/orders", "fixed_status": 403},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        cfg = result.endpoint_configs.get("orders_list")
        assert cfg is not None
        assert cfg.fixed_status == 403

    def test_invalid_fixed_status_ignored(self, registry):
        conn = _make_db([
            {"method": "GET", "path": "/api/v1/orders", "fixed_status": 99},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        cfg = result.endpoint_configs.get("orders_list")
        assert cfg is not None
        assert cfg.fixed_status is None

    def test_unknown_path_skipped(self, registry):
        conn = _make_db([
            {"method": "GET", "path": "/totally/unknown/path"},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        # No endpoint config created — skipped silently
        assert len(result.endpoint_configs) == 0

    def test_multiple_rows_all_mapped(self, registry):
        conn = _make_db([
            {"method": "POST", "path": "/auth/login", "response_mode": "normal"},
            {"method": "GET", "path": "/api/v1/orders", "response_mode": "minimal"},
            {"method": "GET", "path": "/.env", "enabled": 1},
        ])
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert "auth_login" in result.endpoint_configs
        assert "orders_list" in result.endpoint_configs
        assert "recon_env" in result.endpoint_configs

    def test_base_template_from_system_settings(self, registry):
        conn = _make_db_with_settings({"hp_base_template": "corporate_saas"})
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert result.base_template_id == "corporate_saas"

    def test_unknown_template_in_settings_falls_back_to_ecommerce(self, registry):
        conn = _make_db_with_settings({"hp_base_template": "ghost_template_xyz"})
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert result.base_template_id == "ecommerce"

    def test_canonical_instance_config_takes_precedence_over_legacy_row(self, registry):
        conn = _make_db([
            {"method": "GET", "path": "/api/v1/orders/{order_id}", "response_mode": "minimal"},
        ])
        conn.execute(
            """
            CREATE TABLE system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            )
            """
        )
        canonical = InstanceConfig(
            base_template_id="ecommerce",
            endpoint_configs={
                "orders_get": {
                    "endpoint_id": "orders_get",
                    "enabled": False,
                    "response_profile_id": "standard_advanced",
                    "fixed_status": 451,
                }
            },
        )
        conn.execute(
            "INSERT INTO system_settings (key, value) VALUES (?, ?)",
            ("instance_config", canonical.to_json()),
        )
        conn.commit()

        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        cfg = result.endpoint_configs["orders_get"]
        assert cfg.enabled is False
        assert cfg.response_profile_id == "standard_advanced"
        assert cfg.fixed_status == 451

    def test_extensions_and_global_difficulty_loaded_from_settings(self, registry):
        conn = _make_db_with_settings({
            "hp_base_template": "ecommerce",
            "hp_enabled_extensions": json.dumps(["file_server_ext", "webhooks_ext"]),
            "hp_global_difficulty": "advanced",
        })
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert result.enabled_extension_ids == ["file_server_ext", "webhooks_ext"]
        assert result.global_difficulty == Difficulty.ADVANCED

    def test_canonical_instance_config_supplies_extensions_and_difficulty(self, registry):
        canonical = InstanceConfig(
            base_template_id="corporate_saas",
            enabled_extension_ids=["webhooks_ext"],
            global_difficulty=Difficulty.BASIC,
        )
        conn = _make_db_with_settings({"instance_config": canonical.to_json()})
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert result.base_template_id == "corporate_saas"
        assert result.enabled_extension_ids == ["webhooks_ext"]
        assert result.global_difficulty == Difficulty.BASIC

    def test_legacy_mutation_and_rules_loaded_when_canonical_fields_absent(self, registry):
        conn = _make_db_with_settings({"instance_config": '{"base_template_id":"ecommerce"}'})
        _create_legacy_policy_tables(conn)
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert result.mutation_config.policy == "daily"
        assert result.mutation_config.intensity == 2
        assert result.response_rules[0].match.endpoint_id == "orders_list"
        assert result.response_rules[0].action.force_status == 429

    def test_canonical_mutation_and_rules_take_precedence(self, registry):
        canonical = InstanceConfig(
            base_template_id="ecommerce",
            mutation_config={"policy": "weekly", "intensity": 3},
            response_rules=[
                {
                    "id": "rule_canonical",
                    "match": {"endpoint_id": "users_list"},
                    "action": {"extra_latency_ms": 30},
                }
            ],
        )
        conn = _make_db_with_settings({"instance_config": canonical.to_json()})
        _create_legacy_policy_tables(conn)
        result = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        assert result.mutation_config.policy == "weekly"
        assert result.response_rules[0].id == "rule_canonical"


# ── migration_report ──────────────────────────────────────────────────────────

class TestMigrationReport:
    def test_report_structure(self, registry):
        conn = _make_db([
            {"method": "POST", "path": "/auth/login"},
            {"method": "GET", "path": "/does/not/exist"},
        ])
        report = LegacyConfigAdapter(conn, registry=registry).migration_report()
        assert "total_legacy_rows" in report
        assert "mapped" in report
        assert "unmapped" in report
        assert report["total_legacy_rows"] == 2
        assert report["unmapped_count"] == 1

    def test_unmapped_has_note(self, registry):
        conn = _make_db()
        report = LegacyConfigAdapter(conn, registry=registry).migration_report()
        assert "note" in report
        assert len(report["note"]) > 10


# ── End-to-end: adapter → builder ────────────────────────────────────────────

class TestAdapterToBuilder:
    def test_instance_config_from_adapter_builds_without_error(self, registry):
        """Full pipeline: legacy DB → InstanceConfig → EffectiveRuntimeConfig."""
        from app.runtime.builder import build_effective_runtime_config

        conn = _make_db([
            {"method": "GET", "path": "/api/v1/orders", "enabled": 0},
            {"method": "POST", "path": "/auth/login", "response_mode": "normal"},
        ])
        instance_config = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        config = build_effective_runtime_config(instance_config, registry)

        # orders_list should be disabled
        ep = config.get_endpoint("orders_list")
        assert ep is not None
        assert ep.enabled is False

        # auth_login should have standard_medium profile
        ep2 = config.get_endpoint("auth_login")
        assert ep2 is not None
        assert ep2.response.profile_id == "standard_medium"
