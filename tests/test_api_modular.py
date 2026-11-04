import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app import api_modular


class TestApiModular(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              actor_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              path TEXT,
              method TEXT,
              ip TEXT,
              ua TEXT,
              status INTEGER,
              body_sample TEXT,
              token TEXT,
              extra_json TEXT
            )
            """
        )
        api_modular.ensure_tables(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_endpoint_config_roundtrip(self):
        api_modular.upsert_endpoint_config(
            self.conn,
            path="/api/v1/users",
            method="GET",
            config={
                "enabled": True,
                "response_mode": "minimal",
                "fixed_status": None,
                "richness_level": 1,
            },
        )
        resolved = api_modular.resolve_endpoint_config(self.conn, path="/api/v1/users", method="GET")
        self.assertEqual(resolved["match_type"], "exact")
        self.assertEqual(resolved["config"]["response_mode"], "minimal")
        self.assertEqual(resolved["config"]["richness_level"], 1)

    def test_rules_affect_policy(self):
        api_modular.upsert_endpoint_config(
            self.conn,
            path="/admin/users",
            method="GET",
            config={"enabled": True, "response_mode": "normal", "richness_level": 2},
        )
        api_modular.add_rule(
            self.conn,
            {
                "match": {"path": "/admin/*", "method": "GET", "user_agent": "sqlmap"},
                "action": {"change_richness": -2, "force_status": 503, "increase_latency": 250},
            },
        )
        policy = api_modular.resolve_request_policy(
            self.conn,
            path="/admin/users",
            method="GET",
            user_agent="sqlmap/1.0",
            pro_enabled=True,
        )
        self.assertEqual(policy["endpoint_config"]["richness_level"], 0)
        self.assertEqual(policy["endpoint_config"]["fixed_status"], 503)
        self.assertEqual(policy["latency_ms"], 250)
        self.assertTrue(policy["rules"]["matched_rule_ids"])

    def test_path_template_config_matches_runtime_path(self):
        api_modular.upsert_endpoint_config(
            self.conn,
            path="/files/{file_id}/analysis",
            method="GET",
            config={"enabled": True, "response_mode": "minimal", "richness_level": 1},
        )
        resolved = api_modular.resolve_endpoint_config(
            self.conn,
            path="/files/abc123/analysis",
            method="GET",
        )
        self.assertEqual(resolved["match_type"], "pattern_same_method")
        self.assertEqual(resolved["config"]["response_mode"], "minimal")

    def test_path_pattern_helper_supports_template(self):
        self.assertTrue(api_modular.path_matches_pattern("/files/{id}", "/files/xyz"))
        self.assertFalse(api_modular.path_matches_pattern("/files/{id}", "/files/xyz/more"))

    def test_mutation_payload_and_status(self):
        status = api_modular.compute_status(
            original_status=200,
            response_mode="error_bias",
            fixed_status=None,
            mutation_policy="daily",
            mutation_intensity=2,
            path="/x",
            method="GET",
            actor_id="actor",
        )
        self.assertIn(status, {429, 500})
        out = api_modular.mutate_json_payload(
            {"status": "ok", "detail": "ready", "a": 1, "b": 2},
            response_mode="minimal",
            richness_level=0,
            mutation_policy="daily",
            mutation_intensity=2,
            path="/x",
            method="GET",
            actor_id="actor",
        )
        self.assertIsInstance(out, dict)
        # _variant must never appear in the public response body
        self.assertNotIn("_variant", out)
        # payload was still mutated (mutation_policy=daily, intensity=2)
        # minimal mode with richness_level=0 reduces to a single-key dict
        self.assertEqual(len(out), 1)

    def test_response_mode_and_richness_generate_distinct_shapes(self):
        payload = {
            "service": "platform-api",
            "region": "eu-west-1",
            "auth": {"issuer": "x", "audience": "y"},
            "features": {"webhooks": True},
            "contact": {"support": "ops@example.com"},
        }
        normal_2 = api_modular.mutate_json_payload(
            payload,
            response_mode="normal",
            richness_level=2,
            mutation_policy="none",
            mutation_intensity=0,
            path="/config.json",
            method="GET",
            actor_id="actor",
        )
        normal_1 = api_modular.mutate_json_payload(
            payload,
            response_mode="normal",
            richness_level=1,
            mutation_policy="none",
            mutation_intensity=0,
            path="/config.json",
            method="GET",
            actor_id="actor",
        )
        normal_0 = api_modular.mutate_json_payload(
            payload,
            response_mode="normal",
            richness_level=0,
            mutation_policy="none",
            mutation_intensity=0,
            path="/config.json",
            method="GET",
            actor_id="actor",
        )
        minimal_2 = api_modular.mutate_json_payload(
            payload,
            response_mode="minimal",
            richness_level=2,
            mutation_policy="none",
            mutation_intensity=0,
            path="/config.json",
            method="GET",
            actor_id="actor",
        )
        minimal_1 = api_modular.mutate_json_payload(
            payload,
            response_mode="minimal",
            richness_level=1,
            mutation_policy="none",
            mutation_intensity=0,
            path="/config.json",
            method="GET",
            actor_id="actor",
        )
        minimal_0 = api_modular.mutate_json_payload(
            payload,
            response_mode="minimal",
            richness_level=0,
            mutation_policy="none",
            mutation_intensity=0,
            path="/config.json",
            method="GET",
            actor_id="actor",
        )

        self.assertEqual(len(normal_2.keys()), 5)
        self.assertEqual(len(normal_1.keys()), 3)
        self.assertEqual(len(normal_0.keys()), 1)
        self.assertEqual(len(minimal_2.keys()), 3)
        self.assertEqual(len(minimal_1.keys()), 1)
        self.assertEqual(minimal_0, {"ok": True})

    def test_analytics_functions(self):
        now = datetime.now(timezone.utc)
        rows = [
            ((now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"), "actor1", "recon_openapi", "/openapi.json", "GET", "1.1.1.1", "ua-a", 200, '{"latency_ms":120}'),
            ((now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "actor2", "admin_users", "/admin/users", "GET", "1.1.1.1", "ua-b", 401, '{"latency_ms":220}'),
            (now.strftime("%Y-%m-%dT%H:%M:%SZ"), "actor3", "admin_users", "/admin/users", "GET", "1.1.1.1", "ua-c", 500, '{"latency_ms":260}'),
        ]
        for ts, actor_id, kind, path, method, ip, ua, status, extra_json in rows:
            self.conn.execute(
                """
                INSERT INTO events(ts, actor_id, kind, path, method, ip, ua, status, body_sample, token, extra_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (ts, actor_id, kind, path, method, ip, ua, status, "", "", extra_json),
            )
        self.conn.commit()

        endpoint_metrics = api_modular.analytics_endpoint_metrics(self.conn, window_hours=2000, limit=10)
        self.assertTrue(endpoint_metrics)
        interest = api_modular.analytics_interest_scoring(self.conn, window_hours=2000, limit=10)
        self.assertTrue(interest)
        fingerprints = api_modular.analytics_fingerprinting(self.conn, window_hours=2000, limit=10)
        self.assertTrue(fingerprints)

    def test_ensure_tables_repairs_legacy_modular_schema(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        try:
            conn.execute(
                """
                CREATE TABLE api_endpoint_configs (
                  method TEXT,
                  path TEXT,
                  enabled INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE api_mutation_settings (
                  singleton_id INTEGER PRIMARY KEY
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE api_rules (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  enabled INTEGER
                )
                """
            )
            api_modular.ensure_tables(conn)

            saved = api_modular.upsert_endpoint_config(
                conn,
                path="/config.json",
                method="GET",
                config={"enabled": True, "response_mode": "minimal", "fixed_status": 418, "richness_level": 0},
            )
            self.assertEqual(saved["config"]["response_mode"], "minimal")
            policy = api_modular.resolve_request_policy(
                conn,
                path="/config.json",
                method="GET",
                user_agent="unit-test",
                pro_enabled=True,
            )
            self.assertEqual(policy["endpoint_config"]["response_mode"], "minimal")
            self.assertEqual(policy["endpoint_config"]["fixed_status"], 418)
            self.assertEqual(policy["endpoint_config"]["richness_level"], 0)
        finally:
            conn.close()

    def test_mutate_json_payload_never_injects_variant(self):
        """_variant must never appear in the public payload regardless of policy/intensity."""
        for policy, intensity in [("daily", 1), ("daily", 2), ("daily", 3), ("weekly", 1), ("weekly", 3)]:
            out = api_modular.mutate_json_payload(
                {"status": "ok", "message": "hello", "data": [1, 2, 3]},
                response_mode="normal",
                richness_level=2,
                mutation_policy=policy,
                mutation_intensity=intensity,
                path="/api/v1/users",
                method="GET",
                actor_id="actor",
            )
            self.assertIsInstance(out, dict)
            self.assertNotIn("_variant", out, f"_variant leaked with policy={policy}, intensity={intensity}")

    def test_pro_failure_does_not_break_core_policy(self):
        api_modular.upsert_endpoint_config(
            self.conn,
            path="/config.json",
            method="GET",
            config={"enabled": True, "response_mode": "minimal", "fixed_status": 451, "richness_level": 0},
        )
        with patch("app.api_modular.list_rules", side_effect=sqlite3.OperationalError("broken_rules")):
            policy = api_modular.resolve_request_policy(
                self.conn,
                path="/config.json",
                method="GET",
                user_agent="unit-test",
                pro_enabled=True,
            )
        self.assertEqual(policy["endpoint_config"]["response_mode"], "minimal")
        self.assertEqual(policy["endpoint_config"]["fixed_status"], 451)
        self.assertEqual(policy["endpoint_config"]["richness_level"], 0)
        self.assertEqual(policy["rules"]["matched_rule_ids"], [])


if __name__ == "__main__":
    unittest.main()
