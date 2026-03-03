"""
Revocation / suspension propagation tests.

Invariants verified:
  - revoked_overrides_token        : explicit DENY(REVOKED) never falls back to cached lease
  - suspended_overrides_token      : explicit DENY(SUSPENDED) never falls back to cached lease
  - offline_lease_allows_until_deadline : network error + valid cache within grace → Pro
  - after_lease_forced_fallback_to_core : network error + grace expired → Core (raises)
  - plan_features_update_after_revalidation : new features from server reflected in snapshot
  - explicit_deny_propagates_reason_code : reason_code surfaces in pro_license layer
  - snapshot_shows_revoked_reason_code   : end-to-end: snapshot reason_code == "REVOKED"
"""
from __future__ import annotations

import base64
import json
import os
import time
import unittest
from unittest import mock

from app import campaigns_pro, pro_license


def _make_fake_jws(payload: dict) -> str:
    """Build a 3-part JWS-shaped token with a real base64url payload but a fake signature.

    The campaigns_pro helpers (_best_effort_lease_exp, _best_effort_lease_issued_at,
    _cache_entry_usable) decode the payload without verifying the signature, so this is
    sufficient for unit-testing cache logic.
    """
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


class _CampaignsProExplicitDenyTests(unittest.TestCase):
    """Tests at the campaigns_pro layer: get_backend_lease_cached."""

    _BACKEND_URL = "https://pro.example.com"
    _LICENSE_KEY = "sk_test_123"
    _APP_ID = "noctisapi-pro"
    _APP_VERSION = "1.2.3"
    _INSTANCE_ID = "instance-1"
    _FINGERPRINT = "f" * 64

    def setUp(self) -> None:
        # Point disk cache to /dev/null so no real files are created or read.
        os.environ["HP_PRO_LEASE_CACHE_PATH"] = os.devnull
        self._clear_mem_cache()

    def tearDown(self) -> None:
        os.environ.pop("HP_PRO_LEASE_CACHE_PATH", None)
        self._clear_mem_cache()

    def _clear_mem_cache(self) -> None:
        with campaigns_pro._LEASE_CACHE_LOCK:
            campaigns_pro._LEASE_CACHE.update({
                "lease_jws": "",
                "exp": 0,
                "cached_at": 0,
                "backend_url": "",
                "app_id": "",
                "app_version": "",
                "instance_id": "",
                "instance_fingerprint": "",
                "license_key_hash": "",
            })

    def _binding(self) -> dict:
        return campaigns_pro._cache_binding(
            backend_url=self._BACKEND_URL,
            license_key=self._LICENSE_KEY,
            app_id=self._APP_ID,
            app_version=self._APP_VERSION,
            instance_id=self._INSTANCE_ID,
            instance_fingerprint=self._FINGERPRINT,
        )

    def _seed_valid_mem_cache(self, now: int) -> str:
        """Seed in-memory lease cache with a valid fake JWS; returns the jws string."""
        binding = self._binding()
        jws_payload = {
            "exp": now + 3600,
            "issued_at": now - 60,
            "iat": now - 60,
            "offline_grace_seconds": campaigns_pro.CLIENT_CAP_SECONDS,
            "tier": "pro",
            "features": ["cases"],
            "instance_id": self._INSTANCE_ID,
            "fingerprint_sha256": self._FINGERPRINT,
        }
        lease_jws = _make_fake_jws(jws_payload)
        entry = {
            **binding,
            "lease_jws": lease_jws,
            "exp": now + 3600,
            "issued_at": now - 60,
            "offline_grace_seconds": campaigns_pro.CLIENT_CAP_SECONDS,
            "cached_at": now,
        }
        with campaigns_pro._LEASE_CACHE_LOCK:
            campaigns_pro._LEASE_CACHE.update(entry)
        return lease_jws

    def _call_cached(self, *, force_refresh: bool = True) -> tuple[str, str]:
        return campaigns_pro.get_backend_lease_cached(
            backend_url=self._BACKEND_URL,
            license_key=self._LICENSE_KEY,
            app_id=self._APP_ID,
            app_version=self._APP_VERSION,
            instance_id=self._INSTANCE_ID,
            instance_fingerprint=self._FINGERPRINT,
            force_refresh=force_refresh,
        )

    # ------------------------------------------------------------------
    # Test 1 – revoked overrides token
    # ------------------------------------------------------------------
    def test_revoked_overrides_token(self) -> None:
        """Even with a valid in-memory lease, explicit DENY(REVOKED) is never masked."""
        now = int(time.time())
        self._seed_valid_mem_cache(now)

        with mock.patch(
            "app.campaigns_pro.request_backend_lease",
            side_effect=campaigns_pro.CampaignProExplicitDeny("REVOKED"),
        ):
            with self.assertRaises(campaigns_pro.CampaignProExplicitDeny) as cm:
                self._call_cached(force_refresh=True)

        self.assertEqual(cm.exception.reason_code, "REVOKED")

    # ------------------------------------------------------------------
    # Test 2 – suspended overrides token
    # ------------------------------------------------------------------
    def test_suspended_overrides_token(self) -> None:
        """Even with a valid in-memory lease, explicit DENY(SUSPENDED) is never masked."""
        now = int(time.time())
        self._seed_valid_mem_cache(now)

        with mock.patch(
            "app.campaigns_pro.request_backend_lease",
            side_effect=campaigns_pro.CampaignProExplicitDeny("SUSPENDED"),
        ):
            with self.assertRaises(campaigns_pro.CampaignProExplicitDeny) as cm:
                self._call_cached(force_refresh=True)

        self.assertEqual(cm.exception.reason_code, "SUSPENDED")

    # ------------------------------------------------------------------
    # Test 3 – offline lease allows until deadline
    # ------------------------------------------------------------------
    def test_offline_lease_allows_until_deadline(self) -> None:
        """Network error + valid cache within offline grace → Pro is kept."""
        now = int(time.time())
        expected_jws = self._seed_valid_mem_cache(now)

        with mock.patch(
            "app.campaigns_pro.request_backend_lease",
            side_effect=campaigns_pro.CampaignProError("lease_transport_error:ConnectionError"),
        ):
            lease_jws, source = self._call_cached(force_refresh=True)

        self.assertEqual(lease_jws, expected_jws)
        self.assertEqual(source, "cache")

    # ------------------------------------------------------------------
    # Test 4 – after offline grace expires, forced fallback to Core
    # ------------------------------------------------------------------
    def test_after_lease_forced_fallback_to_core(self) -> None:
        """Network error + grace period exceeded → error propagates, no cached lease used."""
        now = int(time.time())
        binding = self._binding()
        expired_issued_at = now - (campaigns_pro.CLIENT_CAP_SECONDS + 10)
        jws_payload = {
            "exp": now + 3600,
            "issued_at": expired_issued_at,
            "iat": expired_issued_at,
            "offline_grace_seconds": campaigns_pro.CLIENT_CAP_SECONDS,
            "tier": "pro",
            "features": ["cases"],
            "instance_id": self._INSTANCE_ID,
            "fingerprint_sha256": self._FINGERPRINT,
        }
        entry = {
            **binding,
            "lease_jws": _make_fake_jws(jws_payload),
            "exp": now + 3600,
            "issued_at": expired_issued_at,
            "offline_grace_seconds": campaigns_pro.CLIENT_CAP_SECONDS,
            "cached_at": now - campaigns_pro.CLIENT_CAP_SECONDS,
        }
        with campaigns_pro._LEASE_CACHE_LOCK:
            campaigns_pro._LEASE_CACHE.update(entry)

        with mock.patch(
            "app.campaigns_pro.request_backend_lease",
            side_effect=campaigns_pro.CampaignProError("lease_transport_error:Timeout"),
        ):
            with self.assertRaises(campaigns_pro.CampaignProError):
                self._call_cached(force_refresh=True)


class _ProLicenseRevocationTests(unittest.TestCase):
    """Tests at the pro_license layer."""

    def setUp(self) -> None:
        self._old_env = {
            k: os.environ.get(k)
            for k in ("LICENSE_KEY", "HP_APP_VERSION", "PRO_BACKEND_URL",
                      "HP_LICENSE_REPORT_TO_SERVER", "HP_PRO_LEASE_CACHE_PATH")
        }
        os.environ["LICENSE_KEY"] = "sk_test_123"
        os.environ["HP_APP_VERSION"] = "1.2.3"
        os.environ["PRO_BACKEND_URL"] = "https://pro.example.com"
        os.environ["HP_LICENSE_REPORT_TO_SERVER"] = "0"
        os.environ["HP_PRO_LEASE_CACHE_PATH"] = os.devnull
        pro_license.clear_cache()

    def tearDown(self) -> None:
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        pro_license.clear_cache()

    _IDENTITY = {"instance_id": "instance-1", "instance_fingerprint_sha256": "f" * 64}

    def _base_payload(self, now: int) -> dict:
        return {
            "exp": now + 3600,
            "issued_at": now - 60,
            "tier": "pro",
            "features": ["campaigns", "cases"],
            "instance_id": "instance-1",
            "fingerprint_sha256": "f" * 64,
        }

    # ------------------------------------------------------------------
    # Test 5 – plan / features update after revalidation
    # ------------------------------------------------------------------
    def test_plan_features_update_after_revalidation(self) -> None:
        """Features returned by the server are reflected in the snapshot after a refresh."""
        now = int(time.time())
        new_payload = {
            "exp": now + 7200,
            "issued_at": now - 10,
            "tier": "pro",
            "features": ["campaigns", "cases", "replay", "analytics"],
            "instance_id": "instance-1",
            "fingerprint_sha256": "f" * 64,
        }

        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._IDENTITY),
            mock.patch(
                "app.pro_license.campaigns_pro.get_backend_lease_cached",
                return_value=("new-lease-jws", "backend"),
            ),
            mock.patch("app.pro_license._lease_payload", return_value=new_payload),
        ):
            lease_jws, exp, error, meta = pro_license._fetch_backend_lease(force_refresh=True)

        self.assertEqual(lease_jws, "new-lease-jws")
        self.assertIsNone(error)
        self.assertEqual(set(meta["lease_features"]), {"campaigns", "cases", "replay", "analytics"})
        self.assertEqual(meta["lease_tier"], "pro")

    # ------------------------------------------------------------------
    # Test 6 – explicit deny propagates reason_code
    # ------------------------------------------------------------------
    def test_explicit_deny_propagates_reason_code(self) -> None:
        """CampaignProExplicitDeny is caught by _fetch_backend_lease and reason_code is returned."""
        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._IDENTITY),
            mock.patch(
                "app.pro_license.campaigns_pro.get_backend_lease_cached",
                side_effect=campaigns_pro.CampaignProExplicitDeny("REVOKED"),
            ),
        ):
            lease_jws, exp, error, meta = pro_license._fetch_backend_lease(force_refresh=True)

        self.assertIsNone(lease_jws)
        self.assertEqual(error, "REVOKED")
        self.assertEqual(meta.get("server_reason_code"), "REVOKED")

    # ------------------------------------------------------------------
    # Test 7 – snapshot shows correct reason_code on revocation
    # ------------------------------------------------------------------
    def test_snapshot_shows_revoked_reason_code(self) -> None:
        """End-to-end: snapshot.reason_code == 'REVOKED' and pro_enabled is False."""
        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._IDENTITY),
            mock.patch(
                "app.pro_license.campaigns_pro.get_backend_lease_cached",
                side_effect=campaigns_pro.CampaignProExplicitDeny("REVOKED"),
            ),
        ):
            snapshot = pro_license.get_backend_license_snapshot(force_refresh=True)

        self.assertFalse(snapshot.get("pro_enabled"))
        self.assertFalse(snapshot.get("valid"))
        self.assertEqual(snapshot.get("decision"), "DENY")
        self.assertEqual(snapshot.get("reason_code"), "REVOKED")
        self.assertEqual(snapshot.get("last_error"), "REVOKED")

    def test_snapshot_shows_suspended_reason_code(self) -> None:
        """End-to-end: snapshot.reason_code == 'SUSPENDED' and pro_enabled is False."""
        with (
            mock.patch("app.pro_license.compute_client_identity", return_value=self._IDENTITY),
            mock.patch(
                "app.pro_license.campaigns_pro.get_backend_lease_cached",
                side_effect=campaigns_pro.CampaignProExplicitDeny("SUSPENDED"),
            ),
        ):
            snapshot = pro_license.get_backend_license_snapshot(force_refresh=True)

        self.assertFalse(snapshot.get("pro_enabled"))
        self.assertEqual(snapshot.get("reason_code"), "SUSPENDED")


if __name__ == "__main__":
    unittest.main()
