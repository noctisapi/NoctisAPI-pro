import unittest
from unittest import mock

from app import pro_ops


class TestProOpsAuthorization(unittest.TestCase):
    def setUp(self):
        pro_ops.clear_cache()

    def tearDown(self):
        pro_ops.clear_cache()

    def test_authorization_denies_when_snapshot_invalid(self):
        snapshot = {
            "pro_enabled": False,
            "valid": False,
            "reason_code": "OFFLINE_LICENSE_MISSING",
            "last_error": "OFFLINE_LICENSE_MISSING",
            "entitlements": {"tier": "core", "features": []},
        }
        with mock.patch("app.pro_ops.pro_license.get_backend_license_snapshot", return_value=snapshot):
            ok, reason = pro_ops.authorize_pro_feature(feature="cases", action="panel_access")
        self.assertFalse(ok)
        self.assertEqual(reason, "OFFLINE_LICENSE_MISSING")

    def test_authorization_denies_unknown_feature(self):
        ok, reason = pro_ops.authorize_pro_feature(feature="unknown_feature", action="x")
        self.assertFalse(ok)
        self.assertEqual(reason, "unknown_feature")

    def test_compat_alias_allows_feature(self):
        deny_snapshot = {
            "pro_enabled": True,
            "valid": True,
            "decision": "ALLOW",
            "reason_code": None,
            "last_error": None,
            "entitlements": {"tier": "pro", "features": ["cases"]},
        }
        with mock.patch("app.pro_ops.pro_license.get_backend_license_snapshot", return_value=deny_snapshot):
            ok, reason = pro_ops.authorize_pro_feature(feature="api_mutation", action="panel_api_modular")
        self.assertFalse(ok)
        self.assertEqual(reason, "feature_not_in_lease")

        allow_snapshot = {
            "pro_enabled": True,
            "valid": True,
            "decision": "ALLOW",
            "reason_code": None,
            "last_error": None,
            "entitlements": {"tier": "pro", "features": ["advanced_scoring"]},
        }
        with mock.patch("app.pro_ops.pro_license.get_backend_license_snapshot", return_value=allow_snapshot):
            ok2, reason2 = pro_ops.authorize_pro_feature(feature="api_mutation", action="panel_api_modular")
        self.assertTrue(ok2)
        self.assertEqual(reason2, "ok")


if __name__ == "__main__":
    unittest.main()
