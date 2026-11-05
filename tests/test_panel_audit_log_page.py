"""NOC-021: /dashboard/audit-log wired into the real admin panel app.

End-to-end: a real login, a real mutating action through the full
middleware chain (_PanelAuthMiddleware -> _PanelAuditMiddleware ->
_PanelRBACMiddleware), and the real audit-log page showing it -- proving
the hand-off between all three, not just each component in isolation
(see test_panel_audit.py and test_panel_audit_middleware.py for those).
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

from fastapi import FastAPI  # noqa: F401 -- forces the real python_multipart to
# load now, before the compat stub below; see test_panel_cloudflare_access_middleware.py.
from fastapi.testclient import TestClient

python_multipart = types.ModuleType("python_multipart")
python_multipart.__version__ = "0.0.20"
sys.modules.setdefault("python_multipart", python_multipart)

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_audit_log_page_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.panel_auth as panel_auth  # noqa: E402
import app.panel_mvp as panel_mvp  # noqa: E402


def _init_db(path: Path) -> None:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
    conn.commit()
    conn.close()


def _client(monkeypatch, tmp_path):
    db_path = tmp_path / "panel_audit_log_page.sqlite"
    _init_db(db_path)
    monkeypatch.setattr(panel_mvp, "DB_PATH", str(db_path))
    startup = list(panel_mvp.app.router.on_startup)
    shutdown = list(panel_mvp.app.router.on_shutdown)
    panel_mvp.app.router.on_startup = []
    panel_mvp.app.router.on_shutdown = []
    client = TestClient(panel_mvp.app)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    panel_auth.ensure_tables(conn)
    return client, conn, startup, shutdown


def _restore(startup, shutdown, conn):
    panel_mvp.app.router.on_startup = startup
    panel_mvp.app.router.on_shutdown = shutdown
    conn.close()


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


class TestAuditLogPage:
    def test_viewer_is_denied(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "vera", "a-long-enough-password", role="viewer")
            _login(client, "vera", "a-long-enough-password")
            resp = client.get("/dashboard/audit-log")
            assert resp.status_code == 403
        finally:
            _restore(startup, shutdown, conn)

    def test_admin_can_view_and_a_real_mutation_shows_up(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")

            # A real mutating, RBAC-gated action through the full stack.
            client.post("/dashboard/members/invite", data={"username": "newbie", "role": "viewer"})

            resp = client.get("/dashboard/audit-log")
            assert resp.status_code == 200
            assert b"/dashboard/members/invite" in resp.content
            assert b"olivia" in resp.content
        finally:
            _restore(startup, shutdown, conn)

    def test_a_denied_action_is_visible_under_failures_only(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            panel_auth.create_user(conn, "aaron", "a-long-enough-password", role="admin")
            _login(client, "aaron", "a-long-enough-password")
            # admin is denied this owner-tier action -- a real 403 from RBAC.
            client.post("/dashboard/members/invite", data={"username": "x", "role": "viewer"})
            client.post("/logout")

            _login(client, "olivia", "a-long-enough-password")
            resp = client.get("/dashboard/audit-log?failures_only=true")
            assert resp.status_code == 200
            assert b"/dashboard/members/invite" in resp.content
            assert b"403" in resp.content
        finally:
            _restore(startup, shutdown, conn)

    def test_plain_dashboard_view_does_not_appear_in_the_log(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")
            client.get("/dashboard/api-modular/resolve")
            resp = client.get("/dashboard/audit-log")
            assert b"/dashboard/api-modular/resolve" not in resp.content
        finally:
            _restore(startup, shutdown, conn)
