import os
import tempfile
import unittest

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
        os.environ.pop("PRO_BACKEND_URL", None)
        ok, reason = pro_ops.authorize_pro_feature(feature="cases", action="panel_access")
        self.assertFalse(ok)
        self.assertIn("missing_PRO_BACKEND_URL", reason)

    def test_authorization_denies_unknown_feature(self):
        ok, reason = pro_ops.authorize_pro_feature(feature="unknown_feature", action="x")
        self.assertFalse(ok)
        self.assertEqual(reason, "unknown_feature")


if __name__ == "__main__":
    unittest.main()
