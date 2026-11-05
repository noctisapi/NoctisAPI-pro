"""NOC-018: individual user login/logout/reset-password wired into the real
admin panel app, and the real _PanelAuthMiddleware gate.

Drives app.panel_mvp's actual FastAPI app through a TestClient -- not a
reimplementation of its logic. Follows the same safe-import pattern as
tests/test_panel_geo_flags.py and tests/test_panel_cloudflare_access_middleware.py
(a temp sqlite file with just an alembic_version table is in place *before*
importing app.panel_mvp, since importing it has heavy side effects).
"""
from __future__ import annotations

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

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_user_identity_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.panel_auth as panel_auth
import app.panel_mvp as panel_mvp


def _init_db(path: Path) -> None:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
    conn.commit()
    conn.close()


def _client(monkeypatch, tmp_path, *, app_env=""):
    db_path = tmp_path / "panel_user_identity.sqlite"
    _init_db(db_path)
    monkeypatch.setattr(panel_mvp, "DB_PATH", str(db_path))
    monkeypatch.setenv("APP_ENV", app_env)
    monkeypatch.delenv("HP_PANEL_COOKIE_SECURE", raising=False)
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


class TestLogin:
    def test_login_page_renders(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            resp = client.get("/login")
            assert resp.status_code == 200
            assert b"username" in resp.content.lower()
        finally:
            _restore(startup, shutdown, conn)

    def test_valid_credentials_set_session_cookie_and_redirect(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "alice", "a-long-enough-password")
            resp = client.post(
                "/login",
                data={"username": "alice", "password": "a-long-enough-password", "next": "/dashboard"},
                follow_redirects=False,
            )
            assert resp.status_code == 303
            assert resp.headers["location"] == "/dashboard"
            assert panel_mvp._PANEL_SESSION_COOKIE in resp.cookies
        finally:
            _restore(startup, shutdown, conn)

    def test_wrong_password_rejected(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "alice", "a-long-enough-password")
            resp = client.post(
                "/login", data={"username": "alice", "password": "wrong-password"}, follow_redirects=False
            )
            assert resp.status_code == 303
            assert "error=1" in resp.headers["location"]
            assert panel_mvp._PANEL_SESSION_COOKIE not in resp.cookies
        finally:
            _restore(startup, shutdown, conn)

    def test_unknown_username_rejected_same_as_wrong_password(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            resp = client.post(
                "/login", data={"username": "nobody", "password": "whatever-password"}, follow_redirects=False
            )
            assert resp.status_code == 303
            assert "error=1" in resp.headers["location"]
        finally:
            _restore(startup, shutdown, conn)

    def test_deactivated_user_cannot_log_in(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            user_id = panel_auth.create_user(conn, "alice", "a-long-enough-password")
            panel_auth.set_user_active(conn, user_id, False)
            resp = client.post(
                "/login", data={"username": "alice", "password": "a-long-enough-password"}, follow_redirects=False
            )
            assert "error=1" in resp.headers["location"]
        finally:
            _restore(startup, shutdown, conn)

    def test_no_shared_token_bypass_for_login(self, monkeypatch, tmp_path):
        """Acceptance criterion: no bypass via a shared token for normal users."""
        monkeypatch.setenv("HP_PANEL_TOKEN", "some-shared-secret-value")
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            resp = client.post(
                "/login",
                data={"username": "whatever", "password": "some-shared-secret-value"},
                follow_redirects=False,
            )
            assert "error=1" in resp.headers["location"]
            assert panel_mvp._PANEL_SESSION_COOKIE not in resp.cookies
        finally:
            _restore(startup, shutdown, conn)


class TestAuthGate:
    def test_unauthenticated_request_redirects_to_login(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            resp = client.get("/__nonexistent_probe__", follow_redirects=False)
            assert resp.status_code == 302
            assert resp.headers["location"].startswith("/login")
        finally:
            _restore(startup, shutdown, conn)

    def test_valid_session_cookie_passes_the_gate(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            user_id = panel_auth.create_user(conn, "alice", "a-long-enough-password")
            token = panel_auth.create_session(conn, user_id)
            client.cookies.set(panel_mvp._PANEL_SESSION_COOKIE, token)
            resp = client.get("/__nonexistent_probe__", follow_redirects=False)
            # Reached FastAPI's router (404), rather than the auth gate (302).
            assert resp.status_code == 404
        finally:
            _restore(startup, shutdown, conn)

    def test_bogus_session_cookie_is_rejected(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            client.cookies.set(panel_mvp._PANEL_SESSION_COOKIE, "not-a-real-session-token")
            resp = client.get("/__nonexistent_probe__", follow_redirects=False)
            assert resp.status_code == 302
        finally:
            _restore(startup, shutdown, conn)


class TestLogout:
    def test_logout_revokes_the_session_not_just_the_cookie(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            user_id = panel_auth.create_user(conn, "alice", "a-long-enough-password")
            token = panel_auth.create_session(conn, user_id)
            client.cookies.set(panel_mvp._PANEL_SESSION_COOKIE, token)

            resp = client.post("/logout", follow_redirects=False)
            assert resp.status_code == 303

            # The *server-side* session must be gone, not merely the cookie --
            # replaying the old raw token must no longer authenticate.
            assert panel_auth.verify_session(conn, token) is None
            client.cookies.set(panel_mvp._PANEL_SESSION_COOKIE, token)
            resp2 = client.get("/__nonexistent_probe__", follow_redirects=False)
            assert resp2.status_code == 302
        finally:
            _restore(startup, shutdown, conn)


class TestResetPassword:
    def test_full_reset_flow_then_login_with_new_password(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            user_id = panel_auth.create_user(conn, "alice", "original-password-123")
            reset_token = panel_auth.create_password_reset(conn, user_id)

            resp = client.post(
                "/reset-password",
                data={
                    "token": reset_token,
                    "password": "brand-new-password-456",
                    "confirm_password": "brand-new-password-456",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 303
            assert "done=1" in resp.headers["location"]

            login_resp = client.post(
                "/login",
                data={"username": "alice", "password": "brand-new-password-456"},
                follow_redirects=False,
            )
            assert panel_mvp._PANEL_SESSION_COOKIE in login_resp.cookies
        finally:
            _restore(startup, shutdown, conn)

    def test_reset_token_cannot_be_reused(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            user_id = panel_auth.create_user(conn, "alice", "original-password-123")
            reset_token = panel_auth.create_password_reset(conn, user_id)
            client.post(
                "/reset-password",
                data={"token": reset_token, "password": "first-new-password-1", "confirm_password": "first-new-password-1"},
                follow_redirects=False,
            )
            resp = client.post(
                "/reset-password",
                data={"token": reset_token, "password": "second-new-password-2", "confirm_password": "second-new-password-2"},
                follow_redirects=False,
            )
            assert "error=1" in resp.headers["location"]
        finally:
            _restore(startup, shutdown, conn)

    def test_mismatched_passwords_rejected(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            user_id = panel_auth.create_user(conn, "alice", "original-password-123")
            reset_token = panel_auth.create_password_reset(conn, user_id)
            resp = client.post(
                "/reset-password",
                data={"token": reset_token, "password": "aaaaaaaaaaaa", "confirm_password": "bbbbbbbbbbbb"},
                follow_redirects=False,
            )
            assert "error=1" in resp.headers["location"]
        finally:
            _restore(startup, shutdown, conn)


class TestCookieSecureFlag:
    def test_cookie_not_secure_outside_prod(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path, app_env="dev")
        try:
            panel_auth.create_user(conn, "alice", "a-long-enough-password")
            resp = client.post(
                "/login", data={"username": "alice", "password": "a-long-enough-password"}, follow_redirects=False
            )
            set_cookie = resp.headers.get("set-cookie", "")
            assert "secure" not in set_cookie.lower()
        finally:
            _restore(startup, shutdown, conn)

    def test_cookie_secure_in_prod(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path, app_env="prod")
        try:
            panel_auth.create_user(conn, "alice", "a-long-enough-password")
            resp = client.post(
                "/login", data={"username": "alice", "password": "a-long-enough-password"}, follow_redirects=False
            )
            set_cookie = resp.headers.get("set-cookie", "")
            assert "secure" in set_cookie.lower()
        finally:
            _restore(startup, shutdown, conn)
