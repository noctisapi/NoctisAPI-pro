import time
import unittest
import tempfile
from uuid import UUID

from app.licensing_client import (
    LicensingManager,
    get_or_create_fingerprint,
    make_mock_post_json,
)


class TestFingerprint(unittest.TestCase):
    def test_get_or_create_fingerprint_persists(self):
        with tempfile.TemporaryDirectory() as td:
            p = td + "/device_fingerprint"
            a = get_or_create_fingerprint(p)
            b = get_or_create_fingerprint(p)
            self.assertEqual(a, b)
            # Valid UUID4-ish string
            UUID(a)


class TestLicensingManager(unittest.TestCase):
    def test_activate_ok_then_validate_403_turns_off(self):
        with tempfile.TemporaryDirectory() as td:
            licensing_url = "https://licensing.example.com"
            activate_url = licensing_url + "/v1/activate"
            validate_url = licensing_url + "/v1/validate"
            deactivate_url = licensing_url + "/v1/deactivate"

            mock = make_mock_post_json(
                {
                    activate_url: (200, {"session_token": "tok_1", "expires_in": 1, "license_id": "lic_1", "plan": "pro"}),
                    validate_url: (403, {"detail": "revoked"}),
                    deactivate_url: (200, {"ok": True}),
                }
            )

            mgr = LicensingManager(
                licensing_url=licensing_url,
                license_key="sk_live_test",
                fingerprint_path=td + "/fp",
                http_timeout_seconds=0.1,
                min_renew_seconds=1,
                post_json_func=mock,
            )
            mgr.start()
            try:
                self.assertTrue(mgr.is_pro_enabled())
                # Wait for renewal loop to run once and fail validation.
                deadline = time.time() + 3.0
                while time.time() < deadline and mgr.is_pro_enabled():
                    time.sleep(0.05)
                self.assertFalse(mgr.is_pro_enabled())
                st = mgr.get_state()
                self.assertEqual(st.last_error, "http_403")
            finally:
                mgr.stop()

    def test_activate_404_starts_core(self):
        with tempfile.TemporaryDirectory() as td:
            licensing_url = "https://licensing.example.com"
            activate_url = licensing_url + "/v1/activate"
            deactivate_url = licensing_url + "/v1/deactivate"

            mock = make_mock_post_json(
                {
                    activate_url: (404, {"detail": "not found"}),
                    deactivate_url: (200, {"ok": True}),
                }
            )

            mgr = LicensingManager(
                licensing_url=licensing_url,
                license_key="sk_live_test",
                fingerprint_path=td + "/fp",
                http_timeout_seconds=0.1,
                min_renew_seconds=1,
                post_json_func=mock,
            )
            mgr.start()
            try:
                self.assertFalse(mgr.is_pro_enabled())
                st = mgr.get_state()
                self.assertEqual(st.last_error, "http_404")
            finally:
                mgr.stop()


if __name__ == "__main__":
    unittest.main()

