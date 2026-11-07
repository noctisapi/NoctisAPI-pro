"""NOC-019: the real _PanelRBACMiddleware wired into a throwaway app.

Drives the actual middleware class from app.panel_mvp, not a
reimplementation, against real path strings from app.panel_rbac's matrix
(one per tier) so the test exercises the production rule table. A tiny
test-only middleware stands in for _PanelAuthMiddleware's job of attaching
scope["state"]["panel_role"] -- that hand-off itself is covered separately
in tests/test_panel_user_identity.py's end-to-end login test.
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
from fastapi.testclient import TestClient

python_multipart = types.ModuleType("python_multipart")
python_multipart.__version__ = "0.0.20"
sys.modules.setdefault("python_multipart", python_multipart)

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_rbac_middleware_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.panel_mvp as panel_mvp  # noqa: E402

_CURRENT_ROLE = {"value": None}


class _FakeIdentityMiddleware:
    """Stands in for _PanelAuthMiddleware: attaches the role this test
    wants for the current request, nothing more."""

    def __init__(self, app=None, app_inner=None):
        self._app = app if app is not None else app_inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            state = dict(scope.get("state") or {})
            state["panel_role"] = _CURRENT_ROLE["value"]
            scope["state"] = state
        await self._app(scope, receive, send)


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(panel_mvp._PanelRBACMiddleware)
    app.add_middleware(_FakeIdentityMiddleware)

    @app.get("/dashboard")  # real VIEWER-tier path
    def viewer_route():
        return {"ok": True}

    @app.post("/dashboard/cases/quick")  # real ANALYST-tier path
    def analyst_route():
        return {"ok": True}

    @app.post("/dashboard/environment/settings")  # real ADMIN-tier path
    def admin_route():
        return {"ok": True}

    @app.post("/pro/log-export/consumers")  # real OWNER-tier path
    def owner_route():
        return {"ok": True}

    @app.get("/this/was/never/classified")  # not in the matrix at all
    def unclassified_route():
        return {"ok": True}

    @app.get("/login")  # pre-auth bypass path
    def login_route():
        return {"ok": True}

    return app


class TestPanelRBACMiddleware(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(_build_test_app())

    def _as(self, role):
        _CURRENT_ROLE["value"] = role
        return self.client

    def test_viewer_can_reach_viewer_tier_route(self):
        resp = self._as("viewer").get("/dashboard")
        self.assertEqual(resp.status_code, 200)

    def test_viewer_cannot_reach_analyst_tier_route(self):
        resp = self._as("viewer").post("/dashboard/cases/quick")
        self.assertEqual(resp.status_code, 403)

    def test_analyst_can_reach_analyst_tier_route(self):
        resp = self._as("analyst").post("/dashboard/cases/quick")
        self.assertEqual(resp.status_code, 200)

    def test_analyst_cannot_reach_admin_tier_route(self):
        resp = self._as("analyst").post("/dashboard/environment/settings")
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_reach_admin_tier_route(self):
        resp = self._as("admin").post("/dashboard/environment/settings")
        self.assertEqual(resp.status_code, 200)

    def test_admin_cannot_reach_owner_tier_route(self):
        resp = self._as("admin").post("/pro/log-export/consumers")
        self.assertEqual(resp.status_code, 403)

    def test_owner_can_reach_every_tier(self):
        self.assertEqual(self._as("owner").get("/dashboard").status_code, 200)
        self.assertEqual(self._as("owner").post("/dashboard/cases/quick").status_code, 200)
        self.assertEqual(self._as("owner").post("/dashboard/environment/settings").status_code, 200)
        self.assertEqual(self._as("owner").post("/pro/log-export/consumers").status_code, 200)

    def test_unclassified_route_denies_everyone_but_owner(self):
        self.assertEqual(self._as("viewer").get("/this/was/never/classified").status_code, 403)
        self.assertEqual(self._as("analyst").get("/this/was/never/classified").status_code, 403)
        self.assertEqual(self._as("admin").get("/this/was/never/classified").status_code, 403)
        self.assertEqual(self._as("owner").get("/this/was/never/classified").status_code, 200)

    def test_missing_role_is_denied_even_on_the_lowest_tier(self):
        resp = self._as(None).get("/dashboard")
        self.assertEqual(resp.status_code, 403)

    def test_bypass_path_skips_rbac_entirely(self):
        resp = self._as(None).get("/login")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
