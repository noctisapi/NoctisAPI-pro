import os
import unittest

from app import pro_ops
from honey_licensing.feature_flags import set_pro_enabled_provider


class TestProOpsAuthorization(unittest.TestCase):
    def setUp(self):
        self._old_backend_url = os.environ.get("PRO_BACKEND_URL")
        self._old_license_key = os.environ.get("LICENSE_KEY")
        pro_ops.clear_cache()
        set_pro_enabled_provider(lambda: True)

    def tearDown(self):
        if self._old_backend_url is None:
            os.environ.pop("PRO_BACKEND_URL", None)
        else:
            os.environ["PRO_BACKEND_URL"] = self._old_backend_url
        if self._old_license_key is None:
            os.environ.pop("LICENSE_KEY", None)
        else:
            os.environ["LICENSE_KEY"] = self._old_license_key
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
