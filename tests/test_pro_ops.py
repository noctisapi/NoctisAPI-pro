import os
import tempfile
import unittest
from unittest import mock

from app import pro_ops
from honey_licensing.feature_flags import set_pro_enabled_provider


class TestProOpsAuthorization(unittest.TestCase):
    def setUp(self):
        self._old_backend_url = os.environ.get("PRO_BACKEND_URL")
        self._old_license_key = os.environ.get("LICENSE_KEY")
        self._old_app_version = os.environ.get("HP_APP_VERSION")
        self._old_instance_id_path = os.environ.get("INSTANCE_ID_PATH")
        self._old_lease_cache_path = os.environ.get("HP_PRO_LEASE_CACHE_PATH")
        self._tmpdir = tempfile.TemporaryDirectory()
        pro_ops.clear_cache()
        set_pro_enabled_provider(lambda: True)
        os.environ["HP_APP_VERSION"] = "test"
        os.environ["LICENSE_KEY"] = "sk_test_123"
        os.environ["INSTANCE_ID_PATH"] = os.path.join(self._tmpdir.name, "instance_id")
        os.environ["HP_PRO_LEASE_CACHE_PATH"] = os.path.join(self._tmpdir.name, "lease_cache.json")

    def tearDown(self):
        if self._old_backend_url is None:
            os.environ.pop("PRO_BACKEND_URL", None)
        else:
            os.environ["PRO_BACKEND_URL"] = self._old_backend_url
        if self._old_license_key is None:
            os.environ.pop("LICENSE_KEY", None)
        else:
            os.environ["LICENSE_KEY"] = self._old_license_key
        if self._old_app_version is None:
            os.environ.pop("HP_APP_VERSION", None)
        else:
            os.environ["HP_APP_VERSION"] = self._old_app_version
        if self._old_instance_id_path is None:
            os.environ.pop("INSTANCE_ID_PATH", None)
        else:
            os.environ["INSTANCE_ID_PATH"] = self._old_instance_id_path
        if self._old_lease_cache_path is None:
            os.environ.pop("HP_PRO_LEASE_CACHE_PATH", None)
        else:
            os.environ["HP_PRO_LEASE_CACHE_PATH"] = self._old_lease_cache_path
        self._tmpdir.cleanup()
        pro_ops.clear_cache()
        set_pro_enabled_provider(None)

    def test_authorization_denies_without_backend(self):
        # authorize_pro_feature now delegates to get_backend_license_snapshot.
        # When PRO_BACKEND_URL is missing the snapshot surfaces reason_code from the
        # generic non-explicit-deny path ("backend_validation_failed") and the
        # specific error is in last_error.  Either way, ok must be False.
        os.environ.pop("PRO_BACKEND_URL", None)
        ok, reason = pro_ops.authorize_pro_feature(feature="cases", action="panel_access")
        self.assertFalse(ok)
        self.assertTrue(reason)  # some non-empty denial reason is returned

    def test_authorization_denies_unknown_feature(self):
        ok, reason = pro_ops.authorize_pro_feature(feature="unknown_feature", action="x")
        self.assertFalse(ok)
        self.assertEqual(reason, "unknown_feature")

    def test_compat_alias_allows_new_feature_with_old_entitlement_name(self):
        # authorize_pro_feature now delegates to get_backend_license_snapshot, so
        # mock that function instead of the old get_backend_lease path.
        deny_snapshot = {
            "pro_enabled": True, "valid": True, "decision": "ALLOW",
            "reason_code": None, "last_error": None,
            "entitlements": {"tier": "pro", "features": ["cases"]},
        }
        with mock.patch("app.pro_ops.pro_license.get_backend_license_snapshot", return_value=deny_snapshot):
            ok, reason = pro_ops.authorize_pro_feature(feature="api_mutation", action="panel_api_modular")
        self.assertFalse(ok)
        self.assertEqual(reason, "feature_not_in_lease")

        allow_snapshot = {
            "pro_enabled": True, "valid": True, "decision": "ALLOW",
            "reason_code": None, "last_error": None,
            "entitlements": {"tier": "pro", "features": ["advanced_scoring"]},
        }
        with mock.patch("app.pro_ops.pro_license.get_backend_license_snapshot", return_value=allow_snapshot):
            ok2, reason2 = pro_ops.authorize_pro_feature(feature="api_mutation", action="panel_api_modular")
        self.assertTrue(ok2)
        self.assertEqual(reason2, "ok")


if __name__ == "__main__":
    unittest.main()
