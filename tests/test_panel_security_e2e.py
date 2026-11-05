"""NOC-022: security audit and adversarial E2E battery for the admin
console's Internet/Access/backend-permission boundary.

Covers what's testable without live Cloudflare infrastructure or a
browser engine (see the module docstring notes below for what isn't):
static-asset bypass path traversal, cookie attribute hardening, an
exhaustive sweep of every classified route against its exact role
boundary (the "rol"/"IDOR" scope items), and accidental-exposure checks
(debug mode, static directory escape).

NOT covered here (documented gap, same class of limitation as NOC-016/017's
Cloudflare Tunnel/Access live-testing notes):
  - Real Cloudflare Tunnel bypass -- needs a live tunnel + edge, not
    reproducible in this sandbox. NOC-016's test_compose_security.py
    already proves the admin port is never published, which is the
    locally-verifiable half of "Tunnel bypass".
  - True SameSite=Strict cross-origin enforcement -- that's a browser
    behavior; httpx/TestClient sends whatever cookie you give it
    regardless of origin, so it cannot prove or disprove SameSite
    enforcement. What IS verified here is the server-side half: the
    cookie is actually issued with samesite="strict" (NOC-018's decision
    to rely on that, instead of a double-submit CSRF token, as the
    primary CSRF mitigation -- see app/panel_auth.py's derive_csrf_token
    docstring).
"""
from __future__ import annotations

import os
import re
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

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_security_e2e_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.panel_auth as panel_auth  # noqa: E402
import app.panel_mvp as panel_mvp  # noqa: E402
import app.panel_rbac as panel_rbac  # noqa: E402
from app.panel_rbac import Role  # noqa: E402


def _init_db(path: Path) -> None:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
    conn.commit()
    conn.close()


def _client(monkeypatch, tmp_path):
    db_path = tmp_path / "panel_security_e2e.sqlite"
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


class TestStaticBypassPathTraversal:
    """Regression coverage for the fix: the raw ASGI bypass check used to be
    a bare path.startswith("/static/"), which a ".." segment could ride
    along with before Starlette's router/StaticFiles ever got a chance to
    reject it -- see app.panel_mvp._is_unauthenticated_path's docstring."""

    def test_helper_rejects_traversal_segments(self):
        assert panel_mvp._is_unauthenticated_path("/static/style.css") is True
        assert panel_mvp._is_unauthenticated_path("/static/../dashboard/members") is False
        assert panel_mvp._is_unauthenticated_path("/static/sub/../../dashboard") is False

    def test_traversal_attempt_does_not_bypass_auth(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            resp = client.get("/static/../dashboard/members", follow_redirects=False)
            # Whatever it resolves to, it must NOT be treated as an
            # unauthenticated static asset -- i.e. it must hit the normal
            # auth gate (302 to /login), not pass straight through.
            assert resp.status_code == 302
            assert resp.headers["location"].startswith("/login")
        finally:
            _restore(startup, shutdown, conn)


class TestCookieHardening:
    def test_session_cookie_is_httponly_and_samesite_strict(self, monkeypatch, tmp_path):
        client, conn, startup, shutdown = _client(monkeypatch, tmp_path)
        try:
            panel_auth.create_user(conn, "olivia", "a-long-enough-password", role="viewer")
            resp = _login(client, "olivia", "a-long-enough-password")
            set_cookie = resp.headers.get("set-cookie", "").lower()
            assert "httponly" in set_cookie
            assert "samesite=strict" in set_cookie
        finally:
            _restore(startup, shutdown, conn)


class TestNoDebugModeExceptionLeak:
    def test_app_debug_is_disabled(self):
        # Starlette's default (debug=False) returns a generic 500, never a
        # traceback, to the client. This guards against anyone ever
        # flipping it on for this attacker-adjacent-reachable app.
        assert panel_mvp.app.debug is False


_CURRENT_ROLE = {"value": None}


class _FakeIdentityMiddleware:
    """Stands in for _PanelAuthMiddleware: attaches whatever role this
    sweep is currently checking (_CURRENT_ROLE, set by each test)."""

    def __init__(self, app_inner):
        self._app = app_inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            state = dict(scope.get("state") or {})
            state["panel_role"] = _CURRENT_ROLE["value"]
            scope["state"] = state
        await self._app(scope, receive, send)


def _concrete_path(template: str) -> str:
    """Substitute a dummy value for every {param} segment -- the exact
    value never matters, only that the shape matches what panel_mvp.py
    actually registers (verified separately by test_panel_rbac.py's
    completeness cross-check against the real app)."""
    return re.sub(r"\{[^/{}]+\}", "1", template)


def _build_full_matrix_app():
    app = FastAPI()
    app.add_middleware(panel_mvp._PanelRBACMiddleware)
    app.add_middleware(_FakeIdentityMiddleware)

    async def _ok():
        return {"ok": True}

    seen = set()
    for method, template, _role in panel_rbac.ROUTE_RULES:
        concrete = _concrete_path(template)
        key = (method, concrete)
        if key in seen:
            continue
        seen.add(key)
        app.add_api_route(concrete, _ok, methods=[method])
    return app


class TestFullRBACMatrixSweep:
    """Exhaustive sweep: every one of the ~95 classified routes, checked
    against the exact role it requires AND the role one tier below it.
    Not a sample -- every single entry in panel_rbac.ROUTE_RULES."""

    def test_every_classified_route_enforces_its_exact_boundary(self):
        client = TestClient(_build_full_matrix_app())
        failures = []
        for method, template, required in panel_rbac.ROUTE_RULES:
            concrete = _concrete_path(template)

            _CURRENT_ROLE["value"] = required.name.lower()
            resp = client.request(method, concrete)
            if resp.status_code == 403:
                failures.append(f"{required.name} denied at its OWN tier: {method} {concrete}")

            if required > Role.VIEWER:
                lower = Role(required - 1)
                _CURRENT_ROLE["value"] = lower.name.lower()
                resp2 = client.request(method, concrete)
                if resp2.status_code != 403:
                    failures.append(
                        f"{lower.name} was NOT denied one tier below {required.name}: "
                        f"{method} {concrete} (status {resp2.status_code})"
                    )

        assert failures == [], "\n".join(failures)

    def test_owner_passes_every_single_route(self):
        client = TestClient(_build_full_matrix_app())
        _CURRENT_ROLE["value"] = "owner"
        for method, template, _required in panel_rbac.ROUTE_RULES:
            resp = client.request(method, _concrete_path(template))
            assert resp.status_code != 403

    def test_viewer_is_denied_every_above_viewer_route(self):
        client = TestClient(_build_full_matrix_app())
        _CURRENT_ROLE["value"] = "viewer"
        denied_count = 0
        for method, template, required in panel_rbac.ROUTE_RULES:
            resp = client.request(method, _concrete_path(template))
            if required > Role.VIEWER:
                assert resp.status_code == 403
                denied_count += 1
        assert denied_count > 0  # sanity: the sweep actually exercised something
