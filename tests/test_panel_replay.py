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

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_replay_test_import.sqlite"
conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
conn.execute("DELETE FROM alembic_version")
conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
conn.commit()
conn.close()
os.environ["HP_DB_PATH"] = str(_IMPORT_DB_PATH)

import app.panel_mvp as panel_mvp


def _init_replay_db(path: Path) -> None:
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
          last_error_ts TEXT
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
        CREATE TABLE cases (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          severity TEXT NOT NULL,
          status TEXT NOT NULL,
          updated_at TEXT NOT NULL
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
        INSERT INTO actors(actor_id, first_seen, last_seen, score, err_total, err_consecutive)
        VALUES('actor-1', '2026-04-02T10:00:00Z', '2026-04-02T10:00:03Z', 12, 0, 0)
        """
    )
    cur.execute(
        """
        INSERT INTO sessions(session_id, actor_id, started_at, ended_at, stage_max, summary, fingerprint)
        VALUES('sess-1', 'actor-1', '2026-04-02T10:00:00Z', '2026-04-02T10:00:03Z', 2, '', 'fp')
        """
    )
    cur.execute(
        """
        INSERT INTO session_steps(
          session_id, seq, ts, method, path, query_json, headers_json, body_json,
          response_status, response_json, stage_before, stage_after, ip, ua, geo_json
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            "sess-1",
            1,
            "2026-04-02T10:00:01Z",
            "GET",
            "/health",
            "{}",
            json.dumps({"user-agent": "ReplayPanelTest/1.0"}),
            None,
            200,
            json.dumps({"status": "ok"}),
            1,
            2,
            "8.8.8.8",
            "ReplayPanelTest/1.0",
            json.dumps({"country_iso2": "US", "country_name": "United States", "flag": "🇺🇸"}),
        ),
    )
    cur.execute(
        """
        INSERT INTO sessions(session_id, actor_id, started_at, ended_at, stage_max, summary, fingerprint)
        VALUES('sess-2', 'actor-1', '2026-04-02T11:00:00Z', '2026-04-02T11:00:01Z', 1, '', 'fp2')
        """
    )
    cur.execute(
        """
        INSERT INTO session_steps(
          session_id, seq, ts, method, path, query_json, headers_json, body_json,
          response_status, response_json, stage_before, stage_after, ip, ua, geo_json
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            "sess-2",
            1,
            "2026-04-02T11:00:00Z",
            "GET",
            "/status",
            "{}",
            "{}",
            None,
            404,
            json.dumps({"detail": "missing"}),
            0,
            1,
            "1.1.1.1",
            "ReplayPanelTest/1.0",
            None,
        ),
    )
    conn.commit()
    conn.close()


def _client(monkeypatch, tmp_path):
    db_path = tmp_path / "replay.sqlite"
    _init_replay_db(db_path)
    monkeypatch.setattr(panel_mvp, "DB_PATH", str(db_path))
    monkeypatch.setattr(panel_mvp, "_has_feature", lambda feature, action=None: True)
    monkeypatch.setattr(panel_mvp, "_tier_has_feature", lambda feature: True)
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


def test_replay_api_exposes_ip_and_geo_from_session_steps(monkeypatch, tmp_path):
    client, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        response = client.get("/api/replay/sess-1")
        assert response.status_code == 200
        payload = response.json()
        assert payload["actor"]["ip"] == "8.8.8.8"
        assert payload["actor"]["geo"]["country_iso2"] == "US"
        assert payload["steps"][0]["ip"] == "8.8.8.8"
        assert payload["steps"][0]["geo"]["country_name"] == "United States"
        assert payload["steps"][0]["response_body"] == {"status": "ok"}
    finally:
        _restore_lifespan(startup, shutdown)


def test_replay_list_renders_ip_and_geo_or_unknown(monkeypatch, tmp_path):
    client, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        response = client.get("/dashboard/replay")
        assert response.status_code == 200
        body = response.text
        assert "8.8.8.8" in body
        assert "United States" in body
        assert "1.1.1.1" in body
    finally:
        _restore_lifespan(startup, shutdown)


def test_replay_detail_renders_source_ip_when_geo_missing(monkeypatch, tmp_path):
    client, startup, shutdown = _client(monkeypatch, tmp_path)
    try:
        response = client.get("/dashboard/replay/sess-2")
        assert response.status_code == 200
        body = response.text
        assert "Source IP" in body
        assert "1.1.1.1" in body
        assert "unknown" in body
    finally:
        _restore_lifespan(startup, shutdown)
