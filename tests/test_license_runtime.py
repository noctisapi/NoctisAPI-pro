import os
import tempfile
import unittest

from app import license_runtime


class TestLicenseRuntime(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old_path = os.environ.get("HP_LICENSE_RUNTIME_CONFIG_PATH")
        self._old_offline_path = os.environ.get("HP_OFFLINE_LICENSE_PATH")
        self._old_app_version = os.environ.get("HP_APP_VERSION")
        os.environ["HP_LICENSE_RUNTIME_CONFIG_PATH"] = os.path.join(self._tmpdir.name, "license_overrides.json")
        os.environ["HP_OFFLINE_LICENSE_PATH"] = "/env/license.json"
        os.environ["HP_APP_VERSION"] = "env-version"
        license_runtime.clear_overrides()

    def tearDown(self):
        license_runtime.clear_overrides()
        self._tmpdir.cleanup()
        if self._old_path is None:
            os.environ.pop("HP_LICENSE_RUNTIME_CONFIG_PATH", None)
        else:
            os.environ["HP_LICENSE_RUNTIME_CONFIG_PATH"] = self._old_path
        if self._old_offline_path is None:
            os.environ.pop("HP_OFFLINE_LICENSE_PATH", None)
        else:
            os.environ["HP_OFFLINE_LICENSE_PATH"] = self._old_offline_path
        if self._old_app_version is None:
            os.environ.pop("HP_APP_VERSION", None)
        else:
            os.environ["HP_APP_VERSION"] = self._old_app_version

    def test_override_takes_precedence_over_env(self):
        license_runtime.save_overrides(
            updates={
                "HP_OFFLINE_LICENSE_PATH": "/override/license.json",
                "HP_APP_VERSION": "override-version",
            }
        )
        self.assertEqual(license_runtime.get_effective("HP_OFFLINE_LICENSE_PATH"), "/override/license.json")
        self.assertEqual(license_runtime.get_effective("HP_APP_VERSION"), "override-version")

    def test_clear_overrides_restores_env_effective_values(self):
        license_runtime.save_overrides(updates={"HP_APP_VERSION": "override-version"})
        self.assertEqual(license_runtime.get_effective("HP_APP_VERSION"), "override-version")
        license_runtime.clear_overrides()
        self.assertEqual(license_runtime.get_effective("HP_APP_VERSION"), "env-version")
        self.assertEqual(license_runtime.get_effective("HP_OFFLINE_LICENSE_PATH"), "/env/license.json")

    def test_invalid_fingerprint_rejected(self):
        with self.assertRaises(ValueError):
            license_runtime.save_overrides(updates={"INSTANCE_FINGERPRINT_SHA256": "not-hex"})

    def test_license_mode_only_accepts_offline(self):
        with self.assertRaises(ValueError):
            license_runtime.save_overrides(updates={"HP_LICENSE_MODE": "hybrid"})


if __name__ == "__main__":
    unittest.main()
