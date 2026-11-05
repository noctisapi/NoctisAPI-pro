"""NOC-019: role hierarchy and the per-route permission matrix.

Pure unit tests against app.panel_rbac, plus a completeness cross-check
that scans the REAL app.panel_mvp FastAPI app and asserts every route it
actually serves has an explicit entry in the matrix (or is one of the
pre-auth bypass routes) -- a route added later and never classified would
fail this test, not silently fall through unexamined.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path

from fastapi import FastAPI  # noqa: F401 -- forces the real python_multipart to
# load now, before the compat stub below, exactly like the other panel test
# modules; see tests/test_panel_cloudflare_access_middleware.py.

from app import panel_rbac
from app.panel_rbac import Role

python_multipart = types.ModuleType("python_multipart")
python_multipart.__version__ = "0.0.20"
sys.modules.setdefault("python_multipart", python_multipart)

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_rbac_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.panel_mvp as panel_mvp  # noqa: E402


class TestRoleHierarchy(unittest.TestCase):
    def test_roles_are_ordered(self):
        self.assertLess(Role.VIEWER, Role.ANALYST)
        self.assertLess(Role.ANALYST, Role.ADMIN)
        self.assertLess(Role.ADMIN, Role.OWNER)

    def test_from_str_accepts_any_case(self):
        self.assertEqual(Role.from_str("admin"), Role.ADMIN)
        self.assertEqual(Role.from_str("ADMIN"), Role.ADMIN)
        self.assertEqual(Role.from_str("  Owner  "), Role.OWNER)

    def test_from_str_rejects_unknown_role(self):
        with self.assertRaises(ValueError):
            Role.from_str("superuser")

    def test_valid_roles_matches_enum(self):
        self.assertEqual(set(panel_rbac.VALID_ROLES), {"viewer", "analyst", "admin", "owner"})

    def test_default_role_is_viewer(self):
        self.assertEqual(panel_rbac.DEFAULT_ROLE, "viewer")


class TestHasPermission(unittest.TestCase):
    def test_exact_role_satisfies_itself(self):
        self.assertTrue(panel_rbac.has_permission("admin", Role.ADMIN))

    def test_higher_role_satisfies_lower_requirement(self):
        self.assertTrue(panel_rbac.has_permission("owner", Role.VIEWER))

    def test_lower_role_does_not_satisfy_higher_requirement(self):
        self.assertFalse(panel_rbac.has_permission("viewer", Role.ADMIN))

    def test_missing_role_is_denied(self):
        self.assertFalse(panel_rbac.has_permission(None, Role.VIEWER))
        self.assertFalse(panel_rbac.has_permission("", Role.VIEWER))

    def test_malformed_role_is_denied_not_raised(self):
        self.assertFalse(panel_rbac.has_permission("not-a-role", Role.VIEWER))


class TestRequiredRoleFor(unittest.TestCase):
    def test_viewer_tier_route(self):
        self.assertEqual(panel_rbac.required_role_for("GET", "/dashboard"), Role.VIEWER)

    def test_analyst_tier_route(self):
        self.assertEqual(
            panel_rbac.required_role_for("POST", "/dashboard/cases/quick"), Role.ANALYST
        )

    def test_admin_tier_route(self):
        self.assertEqual(
            panel_rbac.required_role_for("POST", "/dashboard/environment/settings"), Role.ADMIN
        )

    def test_owner_tier_route(self):
        self.assertEqual(
            panel_rbac.required_role_for("POST", "/pro/log-export/consumers"), Role.OWNER
        )

    def test_path_param_is_matched(self):
        self.assertEqual(
            panel_rbac.required_role_for("POST", "/dashboard/cases/42/rename"), Role.ANALYST
        )
        self.assertEqual(
            panel_rbac.required_role_for("DELETE", "/dashboard/campaigns/abc-123"), Role.ADMIN
        )

    def test_export_suffix_is_a_higher_tier_than_plain_read_on_same_resource(self):
        detail = panel_rbac.required_role_for("GET", "/dashboard/cases/7")
        export = panel_rbac.required_role_for("GET", "/dashboard/cases/7/export.json")
        self.assertEqual(detail, Role.VIEWER)
        self.assertEqual(export, Role.ANALYST)
        self.assertGreater(export, detail)

    def test_wrong_method_on_a_known_path_falls_back_to_default(self):
        # /dashboard is only classified for GET -- DELETE on it is unclassified.
        self.assertEqual(panel_rbac.required_role_for("DELETE", "/dashboard"), Role.OWNER)

    def test_unknown_path_fails_closed_to_owner(self):
        self.assertEqual(
            panel_rbac.required_role_for("GET", "/this/path/was/never/classified"), Role.OWNER
        )
        self.assertEqual(panel_rbac.DEFAULT_REQUIRED_ROLE, Role.OWNER)


class TestMatrixCompletenessAgainstRealApp(unittest.TestCase):
    """If someone adds a new @app.get/post/... to panel_mvp.py and forgets
    to classify it here, this test fails -- it does NOT rely on the
    fail-closed default to quietly paper over the omission."""

    def test_every_real_route_is_classified_or_pre_auth(self):
        classified = {(method, template) for method, template, _role in panel_rbac.ROUTE_RULES}
        classified |= panel_rbac.UNAUTHENTICATED_ROUTES

        missing = []
        for route in panel_mvp.app.routes:
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            if path is None or not methods:
                continue
            for method in methods:
                if method in ("HEAD", "OPTIONS"):
                    continue
                if (method, path) not in classified:
                    missing.append((method, path))

        self.assertEqual(missing, [], f"Unclassified panel routes (add to ROUTE_RULES): {missing}")

    def test_matrix_has_no_entries_for_routes_that_no_longer_exist(self):
        """Catches the opposite drift: a rule left behind after a route was
        renamed/removed, which would silently never match anything."""
        real = set()
        for route in panel_mvp.app.routes:
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            if path is None or not methods:
                continue
            for method in methods:
                if method not in ("HEAD", "OPTIONS"):
                    real.add((method, path))

        stale = [
            (method, template)
            for method, template, _role in panel_rbac.ROUTE_RULES
            if (method, template) not in real
        ]
        self.assertEqual(stale, [], f"Stale RBAC rules (route no longer exists): {stale}")


if __name__ == "__main__":
    unittest.main()
