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

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_geo_flags_import.sqlite"
conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
conn.execute("DELETE FROM alembic_version")
conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
conn.commit()
conn.close()
os.environ["HP_DB_PATH"] = str(_IMPORT_DB_PATH)

import app.panel_mvp as panel_mvp


def _init_db(path: Path) -> None:
    conn = sqlite3.connect(str(path), check_same_thread=False)
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
          lifecycle_state TEXT,
          typical_behavior TEXT
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
        INSERT INTO actors(actor_id, first_seen, last_seen, score, err_total, err_consecutive, lifecycle_state)
        VALUES('actor-geo', '2026-04-03T10:00:00Z', '2026-04-03T10:00:05Z', 12, 0, 0, 'active')
        """
    )
    cur.execute(
        """
        INSERT INTO events(ts, actor_id, kind, path, method, ip, ua, status, body_sample, token, extra_json)
        VALUES('2026-04-03T10:00:05Z', 'actor-geo', 'probe', '/health', 'GET', '74.7.175.157', 'GeoFlagTest/1.0', 200, NULL, NULL, '{}')
        """
    )
    conn.commit()
    conn.close()


def _client(monkeypatch, tmp_path):
    db_path = tmp_path / "panel_geo_flags.sqlite"
    _init_db(db_path)
    monkeypatch.setattr(panel_mvp, "DB_PATH", str(db_path))
    startup = list(panel_mvp.app.router.on_startup)
    shutdown = list(panel_mvp.app.router.on_shutdown)
    panel_mvp.app.router.on_startup = []
    panel_mvp.app.router.on_shutdown = []
    client = TestClient(panel_mvp.app)
    client.cookies.set(panel_mvp._PANEL_SESSION_COOKIE, panel_mvp._make_session_token())
    return client, startup, shutdown


def _restore_lifespan(startup, shutdown):
    panel_mvp.app.router.on_startup = startup
    panel_mvp.app.router.on_shutdown = shutdown


def test_parse_geo_from_extra_accepts_raw_geo_object_and_builds_flag():
    geo = panel_mvp.parse_geo_from_extra('{"country_iso2":"US","country_name":"United States"}')
    assert geo["geo_iso2"] == "US"
    assert geo["geo_country_code"] == "US"
    assert geo["geo_name"] == "United States"
    assert geo["geo_flag"] == "🇺🇸"


def test_dashboard_actors_renders_flag_from_ip_lookup_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(
        panel_mvp,
        "_lookup_geo_ui_for_ip",
        lambda ip: {
            "geo_flag": "🇺🇸",
            "geo_flag_display": "🇺🇸",
            "geo_iso2": "US",
            "geo_country_code": "US",
            "geo_name": "United States",
            "geo_title": "United States",
        } if ip == "74.7.175.157" else panel_mvp._decorate_geo_ui({}, ip=ip),
    )
    client, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        response = client.get("/dashboard/actors")
        assert response.status_code == 200
        body = response.text
        assert "74.7.175.157" in body
        assert "United States" in body
        assert "🇺🇸" in body
    finally:
        _restore_lifespan(startup, shutdown)


def test_dashboard_actors_renders_globe_when_country_is_unknown(monkeypatch, tmp_path):
    monkeypatch.setattr(panel_mvp, "_lookup_geo_ui_for_ip", lambda ip: panel_mvp._decorate_geo_ui({}, ip=ip))
    client, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        response = client.get("/dashboard/actors")
        assert response.status_code == 200
        body = response.text
        assert "74.7.175.157" in body
        assert "🌐" in body
    finally:
        _restore_lifespan(startup, shutdown)
