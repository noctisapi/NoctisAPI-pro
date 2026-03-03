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
        self._old_report = os.environ.get("HP_LICENSE_REPORT_TO_SERVER")
        self._old_report_url = os.environ.get("HP_LICENSE_REPORT_URL")
        os.environ["LICENSE_KEY"] = "sk_test_123"
        os.environ["HP_APP_VERSION"] = "1.2.3"
        os.environ["PRO_BACKEND_URL"] = "https://pro.example.com"
        os.environ["HP_LICENSE_SYNC_ON_STATE_CHANGE"] = "1"
        os.environ["HP_LICENSE_REPORT_TO_SERVER"] = "0"
        pro_license.clear_cache()

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
        if self._old_report is None:
            os.environ.pop("HP_LICENSE_REPORT_TO_SERVER", None)
        else:
            os.environ["HP_LICENSE_REPORT_TO_SERVER"] = self._old_report
        if self._old_report_url is None:
            os.environ.pop("HP_LICENSE_REPORT_URL", None)
        else:
            os.environ["HP_LICENSE_REPORT_URL"] = self._old_report_url
        os.environ.pop("HP_LICENSE_SYNC_ON_STATE_CHANGE", None)

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

    def test_snapshot_change_triggers_force_refresh_to_backend(self):
        now = int(time.time())
        cached = {
            "pro_enabled": False,
            "valid": False,
            "decision": "DENY",
            "reason_code": "backend_validation_failed",
            "last_error": "old_error",
            "last_ok_at": None,
            "expires_at": None,
            "expires_in_seconds": None,
            "recheck_after_seconds": 15,
            "entitlements": {"tier": None, "features": []},
            "source": "backend_lease",
        }
        with pro_license._STATUS_LOCK:
            pro_license._STATUS_CACHE["checked_at"] = now - 999
            pro_license._STATUS_CACHE["snapshot"] = cached

        calls: list[bool] = []

        def _fake_fetch(*, force_refresh: bool):
            calls.append(bool(force_refresh))
            # Both calls are now forced (lease-level cache always bypassed on snapshot refresh).
            return "lease-jws", now + 3600, None, {"lease_tier": "pro", "lease_features": ["cases"]}

        with mock.patch("app.pro_license._fetch_backend_lease", side_effect=_fake_fetch):
            snap = pro_license.get_backend_license_snapshot(force_refresh=False)

        # First call: always force_refresh=True (server check every 15 s).
        # State changed vs cached → sync_on_change triggers a second force_refresh=True.
        self.assertEqual(calls, [True, True])
        self.assertTrue(snap.get("valid"))
        self.assertEqual(snap.get("decision"), "ALLOW")

    def test_snapshot_unchanged_does_not_force_refresh_again(self):
        now = int(time.time())
        cached = {
            "pro_enabled": False,
            "valid": False,
            "decision": "DENY",
            "reason_code": "backend_validation_failed",
            "last_error": "lease_missing_exp",
            "last_ok_at": None,
            "expires_at": None,
            "expires_in_seconds": None,
            "recheck_after_seconds": 15,
            "entitlements": {"tier": None, "features": []},
            "source": "backend_lease",
        }
        with pro_license._STATUS_LOCK:
            pro_license._STATUS_CACHE["checked_at"] = now - 999
            pro_license._STATUS_CACHE["snapshot"] = cached

        calls: list[bool] = []

        def _fake_fetch(*, force_refresh: bool):
            calls.append(bool(force_refresh))
            return None, None, "lease_missing_exp", {"lease_tier": None, "lease_features": []}

        with mock.patch("app.pro_license._fetch_backend_lease", side_effect=_fake_fetch):
            snap = pro_license.get_backend_license_snapshot(force_refresh=False)

        # Snapshot cache expired → first call is now always force_refresh=True.
        # State unchanged (same DENY/lease_missing_exp) → no second sync_on_change call.
        self.assertEqual(calls, [True])
        self.assertFalse(snap.get("valid"))
        self.assertEqual(snap.get("last_error"), "lease_missing_exp")

    def test_force_refresh_reports_snapshot_to_server(self):
        now = int(time.time())
        os.environ["HP_LICENSE_REPORT_TO_SERVER"] = "1"
        with pro_license._STATUS_LOCK:
            pro_license._STATUS_CACHE["checked_at"] = now - 999
            pro_license._STATUS_CACHE["snapshot"] = {}

        with (
            mock.patch("app.pro_license._fetch_backend_lease", return_value=("lease-jws", now + 3600, None, {"lease_tier": "pro", "lease_features": ["cases"]})),
            mock.patch("app.pro_license._report_runtime_status", return_value=None) as rep,
        ):
            snap = pro_license.get_backend_license_snapshot(force_refresh=True)

        self.assertTrue(snap.get("valid"))
        rep.assert_called_once()

    def test_report_uses_dedicated_report_url_when_configured(self):
        now = int(time.time())
        os.environ["HP_LICENSE_REPORT_TO_SERVER"] = "1"
        os.environ["HP_LICENSE_REPORT_URL"] = "https://report.example.com/"
        with pro_license._STATUS_LOCK:
            pro_license._STATUS_CACHE["checked_at"] = now - 999
            pro_license._STATUS_CACHE["snapshot"] = {}

        def _identity():
            return {"instance_id": "instance-1", "instance_fingerprint_sha256": "f" * 64}

        with (
            mock.patch("app.pro_license.compute_client_identity", side_effect=_identity),
            mock.patch("app.pro_license._fetch_backend_lease", return_value=("lease-jws", now + 3600, None, {"lease_tier": "pro", "lease_features": ["cases"]})),
            mock.patch("app.pro_license.campaigns_pro.report_runtime_state", return_value=None) as rep,
        ):
            pro_license.get_backend_license_snapshot(force_refresh=True)

        self.assertEqual(rep.call_count, 1)
        kwargs = rep.call_args.kwargs
        self.assertEqual(kwargs.get("backend_url"), "https://report.example.com")


if __name__ == "__main__":
    unittest.main()
