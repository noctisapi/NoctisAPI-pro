import os
import time
import unittest
from unittest import mock

from app import pro_license


class TestProLicenseLeaseValidation(unittest.TestCase):
    def setUp(self):
        self._old_license_key = os.environ.get("LICENSE_KEY")
        self._old_app_version = os.environ.get("HP_APP_VERSION")
        self._old_backend_url = os.environ.get("PRO_BACKEND_URL")
        os.environ["LICENSE_KEY"] = "sk_test_123"
        os.environ["HP_APP_VERSION"] = "1.2.3"
        os.environ["PRO_BACKEND_URL"] = "https://pro.example.com"

    def tearDown(self):
        if self._old_license_key is None:
            os.environ.pop("LICENSE_KEY", None)
        else:
            os.environ["LICENSE_KEY"] = self._old_license_key
        if self._old_app_version is None:
            os.environ.pop("HP_APP_VERSION", None)
        else:
            os.environ["HP_APP_VERSION"] = self._old_app_version
        if self._old_backend_url is None:
            os.environ.pop("PRO_BACKEND_URL", None)
        else:
            os.environ["PRO_BACKEND_URL"] = self._old_backend_url

    @staticmethod
    def _identity():
        return {"instance_id": "instance-1", "instance_fingerprint_sha256": "f" * 64}

    @staticmethod
    def _base_payload(now: int) -> dict:
        return {
            "exp": now + 3600,
            "issued_at": now - 60,
            "tier": "pro",
            "features": ["campaigns", "cases"],
            "instance_id": "instance-1",
            "fingerprint_sha256": "f" * 64,
        }

    def test_offline_grace_expired_falls_back_to_core(self):
        now = int(time.time())
        payload = self._base_payload(now)
        payload["issued_at"] = now - (pro_license.CLIENT_CAP_SECONDS + 10)

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._identity()),
            mock.patch("app.pro_license.campaigns_pro.get_backend_lease_cached", return_value=("lease-jws", "cache")),
            mock.patch("app.pro_license._lease_payload", return_value=payload),
        ):
            lease_jws, exp, error, _meta = pro_license._fetch_backend_lease(force_refresh=False)

        self.assertIsNone(lease_jws)
        self.assertEqual(error, "offline_grace_expired")
        self.assertIsNotNone(exp)

    def test_cache_mode_within_offline_grace_is_valid(self):
        now = int(time.time())
        payload = self._base_payload(now)
        payload["offline_grace_seconds"] = 300
        payload["issued_at"] = now - 120

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._identity()),
            mock.patch("app.pro_license.campaigns_pro.get_backend_lease_cached", return_value=("lease-jws", "cache")),
            mock.patch("app.pro_license._lease_payload", return_value=payload),
        ):
            lease_jws, exp, error, meta = pro_license._fetch_backend_lease(force_refresh=False)

        self.assertEqual(lease_jws, "lease-jws")
        self.assertIsNone(error)
        self.assertEqual(meta.get("lease_source"), "cache")
        self.assertEqual(meta.get("lease_effective_grace_seconds"), 300)
        self.assertEqual(exp, payload["exp"])

    def test_missing_issued_at_is_rejected(self):
        now = int(time.time())
        payload = self._base_payload(now)
        payload.pop("issued_at", None)

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._identity()),
            mock.patch("app.pro_license.campaigns_pro.get_backend_lease_cached", return_value=("lease-jws", "backend")),
            mock.patch("app.pro_license._lease_payload", return_value=payload),
        ):
            lease_jws, _exp, error, _meta = pro_license._fetch_backend_lease(force_refresh=False)

        self.assertIsNone(lease_jws)
        self.assertEqual(error, "lease_missing_issued_at")

    def test_expires_at_fallback_is_accepted(self):
        now = int(time.time())
        payload = self._base_payload(now)
        payload["expires_at"] = payload.pop("exp")

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._identity()),
            mock.patch("app.pro_license.campaigns_pro.get_backend_lease_cached", return_value=("lease-jws", "backend")),
            mock.patch("app.pro_license._lease_payload", return_value=payload),
        ):
            lease_jws, exp, error, _meta = pro_license._fetch_backend_lease(force_refresh=False)

        self.assertEqual(lease_jws, "lease-jws")
        self.assertIsNone(error)
        self.assertEqual(exp, payload["expires_at"])

    def test_iat_fallback_is_accepted(self):
        now = int(time.time())
        payload = self._base_payload(now)
        payload["iat"] = payload.pop("issued_at")

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._identity()),
            mock.patch("app.pro_license.campaigns_pro.get_backend_lease_cached", return_value=("lease-jws", "backend")),
            mock.patch("app.pro_license._lease_payload", return_value=payload),
        ):
            lease_jws, exp, error, _meta = pro_license._fetch_backend_lease(force_refresh=False)

        self.assertEqual(lease_jws, "lease-jws")
        self.assertIsNone(error)
        self.assertEqual(exp, payload["exp"])

    def test_expires_at_iso_fallback_is_accepted(self):
        now = int(time.time())
        payload = self._base_payload(now)
        payload["expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(payload.pop("exp")))

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._identity()),
            mock.patch("app.pro_license.campaigns_pro.get_backend_lease_cached", return_value=("lease-jws", "backend")),
            mock.patch("app.pro_license._lease_payload", return_value=payload),
        ):
            lease_jws, exp, error, _meta = pro_license._fetch_backend_lease(force_refresh=False)

        self.assertEqual(lease_jws, "lease-jws")
        self.assertIsNone(error)
        self.assertGreater(int(exp or 0), now)

    def test_request_timestamp_fallback_is_accepted(self):
        now = int(time.time())
        payload = self._base_payload(now)
        payload.pop("issued_at", None)
        payload["request_timestamp"] = now - 30

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._identity()),
            mock.patch("app.pro_license.campaigns_pro.get_backend_lease_cached", return_value=("lease-jws", "backend")),
            mock.patch("app.pro_license._lease_payload", return_value=payload),
        ):
            lease_jws, exp, error, _meta = pro_license._fetch_backend_lease(force_refresh=False)

        self.assertEqual(lease_jws, "lease-jws")
        self.assertIsNone(error)
        self.assertEqual(exp, payload["exp"])


if __name__ == "__main__":
    unittest.main()
