"""NOC-021: the real _PanelAuditMiddleware wired into a throwaway app.

Drives the actual middleware class from app.panel_mvp, not a
reimplementation, and checks what actually lands in panel_audit_log --
not just the in-memory should_record() logic (already covered in
tests/test_panel_audit.py).
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

python_multipart = types.ModuleType("python_multipart")
python_multipart.__version__ = "0.0.20"
sys.modules.setdefault("python_multipart", python_multipart)

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_audit_middleware_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.panel_audit as panel_audit  # noqa: E402
import app.panel_mvp as panel_mvp  # noqa: E402

_CURRENT_IDENTITY = {"username": None, "role": None}


class _FakeIdentityMiddleware:
    """Stands in for _PanelAuthMiddleware: attaches whatever identity this
    test wants for the current request."""

    def __init__(self, app_inner):
        self._app = app_inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            state = dict(scope.get("state") or {})
            state["panel_username"] = _CURRENT_IDENTITY["username"]
            state["panel_role"] = _CURRENT_IDENTITY["role"]
            scope["state"] = state
        await self._app(scope, receive, send)


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(panel_mvp._PanelAuditMiddleware)
    app.add_middleware(_FakeIdentityMiddleware)

    @app.get("/some-get")
    def some_get():
        return {"ok": True}

    @app.get("/some-get-403")
    def some_get_403():
        return JSONResponse(status_code=403, content={"detail": "nope"})

    @app.post("/some-post")
    def some_post():
        return {"ok": True}

    @app.post("/some-post-failing")
    def some_post_failing():
        return JSONResponse(status_code=400, content={"detail": "bad"})

    @app.get("/login")  # pre-auth bypass path
    def login_route():
        return {"ok": True}

    return app


class TestPanelAuditMiddleware(unittest.TestCase):
    def setUp(self):
        self.db_path = Path(tempfile.mkdtemp()) / "panel_audit_mw.sqlite"
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
        conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
        conn.commit()
        conn.close()
        self._old_db_path = panel_mvp.DB_PATH
        panel_mvp.DB_PATH = str(self.db_path)
        _CURRENT_IDENTITY["username"] = "olivia"
        _CURRENT_IDENTITY["role"] = "owner"
        self.client = TestClient(_build_test_app())

    def tearDown(self):
        panel_mvp.DB_PATH = self._old_db_path

    def _entries(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            panel_audit.ensure_tables(conn)
            return panel_audit.list_recent(conn)
        finally:
            conn.close()

    def test_successful_get_is_not_logged(self):
        self.client.get("/some-get")
        self.assertEqual(self._entries(), [])

    def test_get_returning_403_is_logged(self):
        self.client.get("/some-get-403")
        entries = self._entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status_code"], 403)
        self.assertEqual(entries[0]["method"], "GET")
        self.assertEqual(entries[0]["path"], "/some-get-403")

    def test_successful_post_is_logged_with_actor(self):
        self.client.post("/some-post")
        entries = self._entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status_code"], 200)
        self.assertEqual(entries[0]["actor_username"], "olivia")
        self.assertEqual(entries[0]["actor_role"], "owner")

    def test_failing_post_is_logged_with_its_real_status(self):
        self.client.post("/some-post-failing")
        entries = self._entries()
        self.assertEqual(entries[0]["status_code"], 400)

    def test_anonymous_request_logs_null_actor(self):
        _CURRENT_IDENTITY["username"] = None
        _CURRENT_IDENTITY["role"] = None
        self.client.post("/some-post")
        entries = self._entries()
        self.assertIsNone(entries[0]["actor_username"])

    def test_bypass_path_is_never_logged(self):
        self.client.get("/login")
        self.assertEqual(self._entries(), [])

    def test_request_id_is_echoed_in_response_header(self):
        resp = self.client.get("/some-get")
        self.assertIn("x-request-id", {k.lower() for k in resp.headers.keys()})

    def test_incoming_request_id_is_honored_not_overwritten(self):
        resp = self.client.post("/some-post", headers={"X-Request-ID": "my-own-id"})
        self.assertEqual(resp.headers["x-request-id"], "my-own-id")
        entries = self._entries()
        self.assertEqual(entries[0]["request_id"], "my-own-id")


if __name__ == "__main__":
    unittest.main()
