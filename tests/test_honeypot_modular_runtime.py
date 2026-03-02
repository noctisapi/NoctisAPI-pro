import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app import api_modular
import app.honeypot_public as honeypot_public


def _prepare_runtime_db(db_path: Path) -> None:
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
          stage_after INTEGER
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
    conn.commit()
    api_modular.ensure_tables(conn)
    api_modular.upsert_endpoint_config(
        conn,
        path="/config.json",
        method="GET",
        config={"enabled": True, "response_mode": "minimal", "fixed_status": 418, "richness_level": 0},
    )
    conn.close()


class TestHoneypotModularRuntime(unittest.TestCase):
    def test_monitor_header_does_not_bypass_modular_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path)

            old_db_path = honeypot_public.DB_PATH
            old_seed = os.environ.get("HP_SEED")
            old_require_seed = os.environ.get("HP_REQUIRE_SEED")
            try:
                honeypot_public.DB_PATH = str(db_path)
                os.environ["HP_SEED"] = "unit-test-seed"
                os.environ["HP_REQUIRE_SEED"] = "0"
                with TestClient(honeypot_public.app) as client:
                    response = client.get(
                        "/config.json",
                        headers={"x-internal-monitor": "1", "x-hp-debug": "1"},
                    )
                self.assertEqual(response.status_code, 418)
                self.assertEqual(response.headers.get("x-hp-modular-fixed-status"), "418")
                self.assertEqual(response.headers.get("x-hp-modular-mode"), "minimal")
                self.assertEqual(response.headers.get("x-hp-modular-policy-source"), "ok")
                self.assertEqual(response.headers.get("x-hp-modular-db-path"), str(db_path))
                self.assertEqual(response.json(), {"ok": True})
            finally:
                honeypot_public.DB_PATH = old_db_path
                if old_seed is None:
                    os.environ.pop("HP_SEED", None)
                else:
                    os.environ["HP_SEED"] = old_seed
                if old_require_seed is None:
                    os.environ.pop("HP_REQUIRE_SEED", None)
                else:
                    os.environ["HP_REQUIRE_SEED"] = old_require_seed

    def test_resolve_endpoint_config_reports_saved_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "honeypot.db"
            _prepare_runtime_db(db_path)

            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            try:
                resolved = api_modular.resolve_endpoint_config(
                    conn,
                    path="/config.json",
                    method="GET",
                    ensure_schema=False,
                )
            finally:
                conn.close()

            self.assertEqual(resolved.get("match_type"), "exact")
            cfg = resolved.get("config") or {}
            self.assertEqual(cfg.get("response_mode"), "minimal")
            self.assertEqual(cfg.get("fixed_status"), 418)


if __name__ == "__main__":
    unittest.main()
