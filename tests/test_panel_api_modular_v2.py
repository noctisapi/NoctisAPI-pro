import json
import os
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

from fastapi.testclient import TestClient

python_multipart = types.ModuleType("python_multipart")
python_multipart.__version__ = "0.0.20"
sys.modules.setdefault("python_multipart", python_multipart)

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_mvp_test_import.sqlite"
conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
conn.execute("DELETE FROM alembic_version")
conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
conn.commit()
conn.close()
os.environ["HP_DB_PATH"] = str(_IMPORT_DB_PATH)

import app.panel_mvp as panel_mvp


def _init_panel_db(path) -> None:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
    conn.commit()
    conn.close()


def _client(monkeypatch, tmp_path):
    db_path = tmp_path / "panel.sqlite"
    _init_panel_db(db_path)
    monkeypatch.setattr(panel_mvp, "DB_PATH", str(db_path))
    monkeypatch.setattr(panel_mvp, "_honeypot_public_endpoint_catalog", lambda: ([], "test", ""))
    monkeypatch.setattr(panel_mvp, "_has_feature", lambda feature, action=None: True)
    monkeypatch.setattr(panel_mvp, "_tier_has_feature", lambda feature: True)
    monkeypatch.setattr(panel_mvp, "_pro_feature_status", lambda feature, action=None: (True, ""))
    startup = list(panel_mvp.app.router.on_startup)
    shutdown = list(panel_mvp.app.router.on_shutdown)
    panel_mvp.app.router.on_startup = []
    panel_mvp.app.router.on_shutdown = []
    client = TestClient(panel_mvp.app)
    client.cookies.set(panel_mvp._PANEL_SESSION_COOKIE, panel_mvp._make_session_token())
    return client, db_path, startup, shutdown


def _restore_lifespan(startup, shutdown):
    panel_mvp.app.router.on_startup = startup
    panel_mvp.app.router.on_shutdown = shutdown


def test_state_v2_exposes_new_model_and_runtime_backends(monkeypatch, tmp_path):
    client, _db_path, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        response = client.get("/dashboard/api-modular/state-v2")
        assert response.status_code == 200
        payload = response.json()
        assert payload["templates"]
        assert payload["extensions"] is not None
        assert payload["instance_config"]["base_template_id"] == "ecommerce"
        assert payload["instance_config"]["mutation_config"]["policy"] == "none"
        runtime = payload["effective_runtime"]
        backends = {item["endpoint_id"]: item["response_backend"] for item in runtime["endpoints"]}
        assert backends["recon_env"] == "factory"
        assert backends["auth_login"] == "runtime_native"
    finally:
        _restore_lifespan(startup, shutdown)


def test_save_instance_config_persists_canonical_runtime_config(monkeypatch, tmp_path):
    invalidations = []
    monkeypatch.setattr(panel_mvp, "invalidate_runtime_cache", lambda: invalidations.append(True))
    client, db_path, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        payload = {
            "base_template_id": "ecommerce",
            "enabled_extension_ids": ["file_server_ext"],
            "global_difficulty": "advanced",
            "mutation_config": {"policy": "daily", "intensity": 2},
            "response_rules": [
                {
                    "id": "rule_users",
                    "match": {"endpoint_id": "users_list", "method": "GET"},
                    "action": {"richness_delta": -1, "extra_latency_ms": 90},
                }
            ],
            "endpoint_configs": {
                "orders_get": {
                    "enabled": False,
                    "response_profile_id": "standard_basic",
                    "fixed_status": 418,
                    "latency_ms": 25,
                    "flaw_profile_id": "idor_basic",
                }
            },
        }
        response = client.post("/dashboard/api-modular/instance-config/save", json=payload)
        assert response.status_code == 200, response.text
        assert invalidations == [True]

        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        settings = {
            row["key"]: row["value"]
            for row in conn.execute("SELECT key, value FROM system_settings").fetchall()
        }
        assert settings["hp_base_template"] == "ecommerce"
        assert json.loads(settings["hp_enabled_extensions"]) == ["file_server_ext"]
        assert settings["hp_global_difficulty"] == "advanced"
        saved_instance = json.loads(settings["instance_config"])
        assert saved_instance["endpoint_configs"]["orders_get"]["fixed_status"] == 418
        assert saved_instance["mutation_config"]["policy"] == "daily"
        assert saved_instance["response_rules"][0]["id"] == "rule_users"

        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='api_endpoint_configs'"
        ).fetchone()
        if table_exists:
            count = conn.execute("SELECT COUNT(*) FROM api_endpoint_configs").fetchone()[0]
            assert count == 0
        conn.close()
    finally:
        _restore_lifespan(startup, shutdown)


def test_save_instance_config_rejects_incompatible_flaw(monkeypatch, tmp_path):
    client, _db_path, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        payload = {
            "base_template_id": "ecommerce",
            "enabled_extension_ids": [],
            "global_difficulty": "medium",
            "endpoint_configs": {
                "auth_login": {
                    "flaw_profile_id": "idor_basic",
                }
            },
        }
        response = client.post("/dashboard/api-modular/instance-config/save", json=payload)
        assert response.status_code == 400
        assert "supported_flaw_profile_ids" in response.json()["detail"] or "incompatible" in response.json()["detail"]
    finally:
        _restore_lifespan(startup, shutdown)


def test_save_instance_config_rejects_unknown_rule_group(monkeypatch, tmp_path):
    client, _db_path, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        payload = {
            "base_template_id": "ecommerce",
            "enabled_extension_ids": [],
            "global_difficulty": "medium",
            "response_rules": [
                {
                    "id": "rule_bad_group",
                    "match": {"endpoint_group_id": "ghost_group"},
                    "action": {"richness_delta": 1},
                }
            ],
            "endpoint_configs": {},
        }
        response = client.post("/dashboard/api-modular/instance-config/save", json=payload)
        assert response.status_code == 400
        assert response.json()["detail"] == "unknown_rule_group:ghost_group"
    finally:
        _restore_lifespan(startup, shutdown)


def test_legacy_write_endpoints_are_deprecated(monkeypatch, tmp_path):
    client, _db_path, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        response = client.post("/dashboard/api-modular/mutation", json={"mutation_policy": "daily", "mutation_intensity": 1})
        assert response.status_code == 410
        assert response.json()["detail"] == "deprecated_use_instance_config_save"
    finally:
        _restore_lifespan(startup, shutdown)
