"""NOC-020: /dashboard/members wired into the real admin panel app.

Drives app.panel_mvp's actual routes through a TestClient -- invite, role
change, deactivate/reactivate, revoke-sessions, the RBAC gate on each
(NOC-019), and the audit trail (membership changes are visible, not just
recorded silently). Follows the same safe-import pattern as the other
panel test modules.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import types
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI  # noqa: F401 -- forces the real python_multipart to
# load now, before the compat stub below; see test_panel_cloudflare_access_middleware.py.
from fastapi.testclient import TestClient

python_multipart = types.ModuleType("python_multipart")
python_multipart.__version__ = "0.0.20"
sys.modules.setdefault("python_multipart", python_multipart)

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_members_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.panel_auth as panel_auth  # noqa: E402
import app.panel_membership_audit as panel_membership_audit  # noqa: E402
import app.panel_mvp as panel_mvp  # noqa: E402


def _init_db(path: Path) -> None:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
    conn.commit()
    conn.close()


def _client(monkeypatch, tmp_path):
    db_path = tmp_path / "panel_members.sqlite"
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
    panel_membership_audit.ensure_tables(conn)
    return client, conn, startup, shutdown


def _restore(startup, shutdown, conn):
    panel_mvp.app.router.on_startup = startup
    panel_mvp.app.router.on_shutdown = shutdown
    conn.close()


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


class TestMembersPageAccess:
    def test_owner_can_view(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")
            resp = client.get("/dashboard/members")
            assert resp.status_code == 200
            assert b"Members" in resp.content
        finally:
            _restore(startup, shutdown, conn)

    def test_admin_can_view(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "aaron", "a-long-enough-password", role="admin")
            _login(client, "aaron", "a-long-enough-password")
            resp = client.get("/dashboard/members")
            assert resp.status_code == 200
        finally:
            _restore(startup, shutdown, conn)

    def test_viewer_is_denied(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "vera", "a-long-enough-password", role="viewer")
            _login(client, "vera", "a-long-enough-password")
            resp = client.get("/dashboard/members")
            assert resp.status_code == 403
        finally:
            _restore(startup, shutdown, conn)


class TestInvite:
    def test_owner_can_invite_and_the_link_actually_works(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")

            resp = client.post(
                "/dashboard/members/invite", data={"username": "newbie", "role": "analyst"}, follow_redirects=False
            )
            assert resp.status_code == 303
            location = resp.headers["location"]
            assert "invite_link=" in location

            qs = parse_qs(urlparse(location).query)
            invite_link = qs["invite_link"][0]
            token = parse_qs(urlparse(invite_link).query)["token"][0]

            newbie = panel_auth.get_user_by_username(conn, "newbie")
            assert newbie is not None
            assert newbie["role"] == "analyst"

            # The invite link is a real, working password-reset token.
            ok = panel_auth.consume_password_reset(conn, token, "newbie-password-123")
            assert ok is True
            resp2 = _login(client, "newbie", "newbie-password-123")
            assert panel_mvp._PANEL_SESSION_COOKIE in resp2.cookies
        finally:
            _restore(startup, shutdown, conn)

    def test_invite_is_audited(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")
            client.post("/dashboard/members/invite", data={"username": "newbie", "role": "viewer"})
            entries = panel_membership_audit.list_recent(conn)
            assert entries[0]["actor_username"] == "olivia"
            assert entries[0]["action"] == "invite"
            assert entries[0]["target_username"] == "newbie"
        finally:
            _restore(startup, shutdown, conn)

    def test_admin_cannot_invite(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "aaron", "a-long-enough-password", role="admin")
            _login(client, "aaron", "a-long-enough-password")
            resp = client.post("/dashboard/members/invite", data={"username": "newbie", "role": "viewer"})
            assert resp.status_code == 403
            assert panel_auth.get_user_by_username(conn, "newbie") is None
        finally:
            _restore(startup, shutdown, conn)

    def test_duplicate_username_is_rejected(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            panel_auth.create_user(conn, "existing", "another-long-password", role="viewer")
            _login(client, "olivia", "a-long-enough-password")
            resp = client.post(
                "/dashboard/members/invite", data={"username": "existing", "role": "viewer"}, follow_redirects=False
            )
            assert "error=1" in resp.headers["location"]
        finally:
            _restore(startup, shutdown, conn)


class TestRoleChange:
    def test_owner_can_change_someone_elses_role(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            target_id = panel_auth.create_user(conn, "vera", "a-long-enough-password", role="viewer")
            _login(client, "olivia", "a-long-enough-password")
            resp = client.post(f"/dashboard/members/{target_id}/role", data={"role": "admin"}, follow_redirects=False)
            assert resp.status_code == 303
            assert panel_auth.get_user_by_id(conn, target_id)["role"] == "admin"
        finally:
            _restore(startup, shutdown, conn)

    def test_cannot_change_own_role(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            owner_id = panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            panel_auth.create_user(conn, "second-owner", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")
            resp = client.post(f"/dashboard/members/{owner_id}/role", data={"role": "viewer"}, follow_redirects=False)
            assert "error=1" in resp.headers["location"]
            assert panel_auth.get_user_by_id(conn, owner_id)["role"] == "owner"
        finally:
            _restore(startup, shutdown, conn)

    def test_owner_can_demote_another_owner_since_the_actor_always_remains(self, monkeypatch, tmp_path):
        """There's no separate "last owner" check -- blocking self-role-change
        (above) is what makes this safe: whoever is left logged in and
        acting is necessarily still an active owner, since they can only
        ever change *someone else's* role."""
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            olivia_id = panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            other_owner_id = panel_auth.create_user(conn, "oscar", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")
            resp = client.post(
                f"/dashboard/members/{other_owner_id}/role", data={"role": "viewer"}, follow_redirects=False
            )
            assert resp.status_code == 303
            assert panel_auth.get_user_by_id(conn, other_owner_id)["role"] == "viewer"
            assert panel_auth.get_user_by_id(conn, olivia_id)["role"] == "owner"
        finally:
            _restore(startup, shutdown, conn)


class TestDeactivateActivate:
    def test_owner_can_deactivate_another_user_and_it_revokes_sessions(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            target_id = panel_auth.create_user(conn, "vera", "a-long-enough-password", role="viewer")
            target_token = panel_auth.create_session(conn, target_id)
            _login(client, "olivia", "a-long-enough-password")

            resp = client.post(f"/dashboard/members/{target_id}/deactivate", follow_redirects=False)
            assert resp.status_code == 303
            assert panel_auth.get_user_by_id(conn, target_id)["is_active"] == 0
            assert panel_auth.verify_session(conn, target_token) is None
        finally:
            _restore(startup, shutdown, conn)

    def test_cannot_deactivate_self(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            owner_id = panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            panel_auth.create_user(conn, "second-owner", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")
            resp = client.post(f"/dashboard/members/{owner_id}/deactivate", follow_redirects=False)
            assert "error=1" in resp.headers["location"]
            assert panel_auth.get_user_by_id(conn, owner_id)["is_active"] == 1
        finally:
            _restore(startup, shutdown, conn)

    def test_owner_can_deactivate_another_owner_since_the_actor_always_remains(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            olivia_id = panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            other_owner_id = panel_auth.create_user(conn, "oscar", "a-long-enough-password", role="owner")
            _login(client, "olivia", "a-long-enough-password")
            resp = client.post(f"/dashboard/members/{other_owner_id}/deactivate", follow_redirects=False)
            assert resp.status_code == 303
            assert panel_auth.get_user_by_id(conn, other_owner_id)["is_active"] == 0
            assert panel_auth.get_user_by_id(conn, olivia_id)["is_active"] == 1
        finally:
            _restore(startup, shutdown, conn)

    def test_reactivate(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            target_id = panel_auth.create_user(conn, "vera", "a-long-enough-password", role="viewer", is_active=False)
            _login(client, "olivia", "a-long-enough-password")
            resp = client.post(f"/dashboard/members/{target_id}/activate", follow_redirects=False)
            assert resp.status_code == 303
            assert panel_auth.get_user_by_id(conn, target_id)["is_active"] == 1
        finally:
            _restore(startup, shutdown, conn)


class TestRevokeSessions:
    def test_owner_can_revoke_someone_elses_sessions(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="owner")
            target_id = panel_auth.create_user(conn, "vera", "a-long-enough-password", role="viewer")
            target_token = panel_auth.create_session(conn, target_id)
            _login(client, "olivia", "a-long-enough-password")

            resp = client.post(f"/dashboard/members/{target_id}/revoke-sessions", follow_redirects=False)
            assert resp.status_code == 303
            assert panel_auth.verify_session(conn, target_token) is None
            # Account stays active -- only the sessions were cut.
            assert panel_auth.get_user_by_id(conn, target_id)["is_active"] == 1
        finally:
            _restore(startup, shutdown, conn)
