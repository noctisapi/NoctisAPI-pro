import os
import json
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import api_modular
import app.honeypot_public as honeypot_public
from app.runtime_provider import reset_provider


def _prepare_runtime_db(db_path: Path, *, with_config_override: bool = True) -> None:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    cur.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
    cur.execute(
        """
        CREATE TABLE actors (
          actor_id TEXT PRIMARY KEY,
          first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          score INTEGER NOT NULL DEFAULT 0,
          err_total INTEGER NOT NULL DEFAULT 0,
          err_consecutive INTEGER NOT NULL DEFAULT 0,
          last_status INTEGER,
          last_error_ts TEXT,
          lifecycle_state TEXT DEFAULT 'active',
          is_archived INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute(
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
    cur.execute(
        """
        CREATE TABLE sessions (
          session_id TEXT PRIMARY KEY,
          actor_id TEXT NOT NULL,
          started_at TEXT NOT NULL,
          ended_at TEXT,
          stage_max INTEGER,
          summary TEXT,
          fingerprint TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE session_steps (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id TEXT NOT NULL,
          seq INTEGER NOT NULL,
          ts TEXT NOT NULL,
          method TEXT,
          path TEXT,
          query_json TEXT,
          headers_json TEXT,
          body_json TEXT,
          response_status INTEGER,
          response_json TEXT,
          stage_before INTEGER,
          stage_after INTEGER,
          ip TEXT,
          ua TEXT,
          geo_json TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor_id TEXT NOT NULL,
          token TEXT NOT NULL,
          created_ts TEXT NOT NULL,
          stage INTEGER NOT NULL DEFAULT 0,
          gift_type TEXT NOT NULL DEFAULT 'standard',
          used_count INTEGER NOT NULL DEFAULT 0,
          last_used_ts TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE issued_secrets (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor_id TEXT NOT NULL,
          kind TEXT NOT NULL,
          value TEXT NOT NULL,
          created_ts TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE system_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.commit()
    api_modular.ensure_tables(conn)
    if with_config_override:
        cur.execute(
            """
            INSERT INTO system_settings(key, value) VALUES(?, ?)
            """,
            (
                "instance_config",
                json.dumps(
                    {
                        "base_template_id": "ecommerce",
                        "endpoint_configs": {
                            "recon_config": {
                                "endpoint_id": "recon_config",
                                "response_profile_id": "standard_basic",
                                "fixed_status": 418,
                            }
                        },
                    }
                ),
            ),
        )
        conn.commit()
    conn.close()


class TestHoneypotModularRuntime(unittest.TestCase):
    def test_legacy_fake_users_use_plausible_identity(self):
        users = honeypot_public._fake_users("actor-test", limit=3, offset=0)

        self.assertEqual(len(users), 3)
        for user in users:
            self.assertRegex(user["name"], r"^[A-Z][a-z]+ [A-Z][a-z]+$")
            self.assertRegex(user["email"], r"^[a-z._]+@[a-z0-9-]+\.[a-z.]+$")
            self.assertIsNone(re.search(r"@(example\.com|acme\.io|testorg\.net)$", user["email"]))

    def test_monitor_header_does_not_bypass_modular_policy(self):
        """Modular policy (418 + minimal mode) applies regardless of monitor header."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path)

            old_monitor_secret = honeypot_public._HP_MONITOR_SECRET
            restore = self._apply_db(db_path)
            try:
                honeypot_public._HP_MONITOR_SECRET = "test-monitor-secret"
                with TestClient(honeypot_public.app) as client:
                    response = client.get(
                        "/config.json",
                        headers={
                            "x-internal-monitor": "test-monitor-secret",
                            "x-hp-debug": "1",
                        },
                    )
                self.assertEqual(response.status_code, 418)
                self.assertEqual(response.headers.get("x-hp-modular-fixed-status"), "418")
                self.assertEqual(response.headers.get("x-hp-modular-mode"), "minimal")
                self.assertEqual(response.headers.get("x-hp-modular-policy-source"), "runtime")
                # x-hp-modular-db-path must NOT be present (security fix)
                self.assertIsNone(response.headers.get("x-hp-modular-db-path"))
                self.assertEqual(response.json(), {"ok": True})
            finally:
                honeypot_public._HP_MONITOR_SECRET = old_monitor_secret
                restore()

    def _apply_db(self, db_path, **kwargs):
        """Override DB_PATH + env vars and return a restore callable."""
        old_db = honeypot_public.DB_PATH
        old_seed = os.environ.get("HP_SEED")
        old_req = os.environ.get("HP_REQUIRE_SEED")
        old_env_db = os.environ.get("HP_DB_PATH")
        honeypot_public.DB_PATH = str(db_path)
        os.environ["HP_DB_PATH"] = str(db_path)
        os.environ["HP_SEED"] = "unit-test-seed"
        os.environ["HP_REQUIRE_SEED"] = "0"
        reset_provider()

        def restore():
            honeypot_public.DB_PATH = old_db
            if old_env_db is None:
                os.environ.pop("HP_DB_PATH", None)
            else:
                os.environ["HP_DB_PATH"] = old_env_db
            if old_seed is None:
                os.environ.pop("HP_SEED", None)
            else:
                os.environ["HP_SEED"] = old_seed
            if old_req is None:
                os.environ.pop("HP_REQUIRE_SEED", None)
            else:
                os.environ["HP_REQUIRE_SEED"] = old_req
            reset_provider()

        return restore

    def _last_event(self, db_path: Path):
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(
                "SELECT kind, path, status, extra_json FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # AC1: request to non-existent endpoint → 404, no mutation, no _variant
    # ------------------------------------------------------------------
    def test_nonexistent_endpoint_returns_404_without_mutation(self):
        """Unregistered paths must return a plain 404 with no mutation applied."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path)
            restore = self._apply_db(db_path)
            try:
                with TestClient(honeypot_public.app, raise_server_exceptions=False) as client:
                    response = client.get("/this/path/does/not/exist/anywhere")
                self.assertEqual(response.status_code, 404)
                body = response.json()
                self.assertNotIn("_variant", body)
                # FastAPI's natural 404 has a "detail" key
                self.assertIn("detail", body)
            finally:
                restore()

    def test_openapi_reflects_active_modular_runtime_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path, with_config_override=False)
            restore = self._apply_db(db_path)
            try:
                with TestClient(honeypot_public.app) as client:
                    response = client.get("/openapi.json")
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                paths = payload.get("paths") or {}
                self.assertIn("/api/v1/orders", paths)
                self.assertIn("get", paths["/api/v1/orders"])
                self.assertIn("post", paths["/api/v1/orders"])
                self.assertIn("/api/v1/users/{user_id}", paths)
                self.assertNotIn("/admin/secrets", paths)
                self.assertNotIn("/backup/list", paths)
            finally:
                restore()

    # ------------------------------------------------------------------
    # AC2: existing endpoint with mutation active → mutated body, no _variant
    # ------------------------------------------------------------------
    def test_existing_endpoint_mutation_active_no_variant_in_body(self):
        """When Pro mutation is active, existing endpoints are mutated but _variant never leaks into body."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path)
            # Enable mutation settings in DB
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            api_modular.upsert_endpoint_config(
                conn,
                path="/status",
                method="GET",
                config={"enabled": True, "response_mode": "normal", "fixed_status": None, "richness_level": 2},
            )
            api_modular.set_mutation_config(conn, mutation_policy="daily", mutation_intensity=2)
            conn.close()

            restore = self._apply_db(db_path)
            try:
                # Patch Pro gate so mutation is actually applied
                with patch("app.honeypot_public._has_modular_pro", return_value=True):
                    with TestClient(honeypot_public.app) as client:
                        response = client.get("/status")
                self.assertEqual(response.status_code, 200)
                body = response.json()
                # _variant must NEVER appear in a public response
                self.assertNotIn("_variant", body)
                # Body must be a dict (mutation may reorder keys but keeps it a dict)
                self.assertIsInstance(body, dict)
            finally:
                restore()

    # ------------------------------------------------------------------
    # AC3: existing endpoint with mutation disabled → normal response, no _variant
    # ------------------------------------------------------------------
    def test_existing_endpoint_mutation_disabled_returns_normal_response(self):
        """When mutation is disabled (policy=none / intensity=0), body is unchanged and has no _variant."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path)
            restore = self._apply_db(db_path)
            try:
                with TestClient(honeypot_public.app) as client:
                    response = client.get("/health")
                self.assertEqual(response.status_code, 200)
                body = response.json()
                self.assertNotIn("_variant", body)
                self.assertEqual(body.get("status"), "ok")
            finally:
                restore()

    def test_runtime_config_reports_saved_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path)
            restore = self._apply_db(db_path)
            try:
                from app.runtime_provider import get_runtime_config

                runtime = get_runtime_config()
                endpoint = runtime.get_endpoint("recon_config")
                self.assertIsNotNone(endpoint)
                self.assertEqual(endpoint.response.profile_id, "standard_basic")
                self.assertEqual(endpoint.response.fixed_status, 418)
            finally:
                restore()

    def test_factory_migrated_recon_endpoint_skips_modular_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path, with_config_override=False)

            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            api_modular.set_mutation_config(conn, mutation_policy="daily", mutation_intensity=2)
            conn.close()

            restore = self._apply_db(db_path)
            try:
                with patch("app.honeypot_public._has_modular_pro", return_value=True):
                    with TestClient(honeypot_public.app) as client:
                        response = client.get("/.env")

                self.assertEqual(response.status_code, 200)
                self.assertNotEqual(response.text, "status=ok\n")
                self.assertIn("DB_HOST=", response.text)

                row = self._last_event(db_path)
                self.assertIsNotNone(row)
                self.assertEqual(row["kind"], "recon_env")
                extra = json.loads(row["extra_json"] or "{}")
                self.assertEqual(extra["interaction"]["endpoint_id"], "recon_env")
                self.assertEqual(extra["interaction"]["response_backend"], "factory")
            finally:
                restore()

    def test_non_migrated_endpoint_uses_runtime_native_backend_in_interaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path, with_config_override=False)
            restore = self._apply_db(db_path)
            try:
                with patch("app.honeypot_public.random.random", return_value=0.0):
                    with TestClient(honeypot_public.app) as client:
                        response = client.post("/auth/login", json={"username": "alice", "password": "secret"})

                self.assertEqual(response.status_code, 200)
                row = self._last_event(db_path)
                self.assertIsNotNone(row)
                self.assertEqual(row["kind"], "auth_login")
                extra = json.loads(row["extra_json"] or "{}")
                self.assertEqual(extra["interaction"]["response_backend"], "runtime_native")
                self.assertEqual(extra["interaction"]["endpoint_id"], "auth_login")
            finally:
                restore()

    def test_generated_orders_list_uses_handler_factory_and_records_interaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path, with_config_override=False)
            restore = self._apply_db(db_path)
            try:
                with TestClient(honeypot_public.app) as client:
                    response = client.get("/api/v1/orders")

                self.assertEqual(response.status_code, 200)
                body = response.json()
                self.assertIsInstance(body.get("data"), list)
                self.assertGreater(len(body["data"]), 0)
                self.assertIn("total", body)
                self.assertNotIn("next_offset", body)

                row = self._last_event(db_path)
                self.assertIsNotNone(row)
                self.assertEqual(row["kind"], "business_reports")
                extra = json.loads(row["extra_json"] or "{}")
                self.assertEqual(extra["interaction"]["endpoint_id"], "orders_list")
                self.assertEqual(extra["interaction"]["response_backend"], "handler_factory")
            finally:
                restore()

    def test_generated_orders_create_uses_catalog_status_and_records_interaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path, with_config_override=False)
            restore = self._apply_db(db_path)
            try:
                with TestClient(honeypot_public.app) as client:
                    response = client.post("/api/v1/orders", json={"sku": "sku_test", "quantity": 2})

                self.assertEqual(response.status_code, 201)
                body = response.json()
                self.assertTrue(str(body.get("id") or "").startswith("ord_"))
                self.assertIn("status", body)
                self.assertIn("total", body)

                row = self._last_event(db_path)
                self.assertIsNotNone(row)
                self.assertEqual(row["kind"], "business_reports")
                extra = json.loads(row["extra_json"] or "{}")
                self.assertEqual(extra["interaction"]["endpoint_id"], "orders_create")
                self.assertEqual(extra["interaction"]["response_backend"], "handler_factory")
            finally:
                restore()

    def test_request_capture_persists_ip_and_geo_into_session_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path, with_config_override=False)
            restore = self._apply_db(db_path)
            try:
                with patch("app.honeypot_public.resolve_client_ip", return_value="8.8.8.8"):
                    with patch(
                        "app.honeypot_public._geoip_country",
                        return_value={
                            "country_iso2": "US",
                            "country_name": "United States",
                            "flag": "🇺🇸",
                        },
                    ):
                        with TestClient(honeypot_public.app) as client:
                            response = client.get("/health", headers={"user-agent": "ReplayGeoTest/1.0"})

                self.assertEqual(response.status_code, 200)

                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                try:
                    event_row = conn.execute(
                        "SELECT ip, ua, extra_json FROM events ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    self.assertIsNotNone(event_row)
                    self.assertEqual(event_row["ip"], "8.8.8.8")
                    extra = json.loads(event_row["extra_json"] or "{}")
                    self.assertEqual(extra["geo"]["country_iso2"], "US")
                    self.assertEqual(extra["geo"]["country_code"], "US")

                    step_row = conn.execute(
                        "SELECT ip, ua, geo_json, response_json FROM session_steps ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    self.assertIsNotNone(step_row)
                    self.assertEqual(step_row["ip"], "8.8.8.8")
                    self.assertIn("ReplayGeoTest/1.0", step_row["ua"])
                    self.assertEqual(json.loads(step_row["geo_json"] or "{}")["country_iso2"], "US")
                    self.assertEqual(json.loads(step_row["geo_json"] or "{}")["country_code"], "US")
                    self.assertEqual(json.loads(step_row["response_json"] or "{}"), {"status": "ok"})
                finally:
                    conn.close()
            finally:
                restore()


if __name__ == "__main__":
    unittest.main()
