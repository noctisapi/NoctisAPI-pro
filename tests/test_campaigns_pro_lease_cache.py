import base64
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from app import campaigns_pro


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _fake_lease_jws(exp: int, issued_at: int, offline_grace_seconds: int | None = None) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "tier": "pro",
        "features": ["campaigns"],
        "exp": int(exp),
        "issued_at": int(issued_at),
    }
    if offline_grace_seconds is not None:
        payload["offline_grace_seconds"] = int(offline_grace_seconds)
    return ".".join(
        [
            _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")),
            _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")),
            "sig",
        ]
    )


class TestCampaignsProLeaseCache(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old_cache_path = os.environ.get("HP_PRO_LEASE_CACHE_PATH")
        os.environ["HP_PRO_LEASE_CACHE_PATH"] = os.path.join(self._tmpdir.name, "lease_cache.json")
        campaigns_pro._LEASE_CACHE.update(
            {
                "lease_jws": "",
                "exp": 0,
                "cached_at": 0,
                "backend_url": "",
                "app_id": "",
                "app_version": "",
                "instance_id": "",
                "instance_fingerprint": "",
                "license_key_hash": "",
            }
        )

    def tearDown(self):
        if self._old_cache_path is None:
            os.environ.pop("HP_PRO_LEASE_CACHE_PATH", None)
        else:
            os.environ["HP_PRO_LEASE_CACHE_PATH"] = self._old_cache_path
        self._tmpdir.cleanup()

    def _cache_entry(
        self,
        *,
        backend_url: str,
        cached_at: int,
        exp: int,
        issued_at: int,
        offline_grace_seconds: int | None = None,
    ) -> dict:
        binding = campaigns_pro._cache_binding(
            backend_url=backend_url,
            license_key="sk_test_123",
            app_id="noctisapi-pro",
            app_version="1.2.3",
            instance_id="instance-1",
            instance_fingerprint="f" * 64,
        )
        return {
            "lease_jws": _fake_lease_jws(exp, issued_at=issued_at, offline_grace_seconds=offline_grace_seconds),
            "exp": int(exp),
            "issued_at": int(issued_at),
            "offline_grace_seconds": offline_grace_seconds,
            "cached_at": int(cached_at),
            **binding,
        }

    def test_uses_disk_cache_when_backend_url_missing(self):
        now = int(time.time())
        entry = self._cache_entry(
            backend_url="https://pro.example.com",
            cached_at=now - 20,
            exp=now + 3600,
            issued_at=now - 60,
            offline_grace_seconds=600,
        )
        campaigns_pro._write_lease_cache_file(os.environ["HP_PRO_LEASE_CACHE_PATH"], entry)

        lease, source = campaigns_pro.get_backend_lease_cached(
            backend_url="",
            license_key="sk_test_123",
            app_id="noctisapi-pro",
            app_version="1.2.3",
            instance_id="instance-1",
            instance_fingerprint="f" * 64,
            force_refresh=False,
        )
        self.assertEqual(lease, entry["lease_jws"])
        self.assertEqual(source, "cache")

    def test_rejects_cache_when_offline_grace_exceeded_without_backend(self):
        now = int(time.time())
        entry = self._cache_entry(
            backend_url="https://pro.example.com",
            cached_at=now - 20,
            exp=now + 3600,
            issued_at=now - (campaigns_pro.CLIENT_CAP_SECONDS + 10),
            offline_grace_seconds=None,
        )
        campaigns_pro._write_lease_cache_file(os.environ["HP_PRO_LEASE_CACHE_PATH"], entry)

        with self.assertRaises(campaigns_pro.CampaignProError):
            campaigns_pro.get_backend_lease_cached(
                backend_url="",
                license_key="sk_test_123",
                app_id="noctisapi-pro",
                app_version="1.2.3",
                instance_id="instance-1",
                instance_fingerprint="f" * 64,
                force_refresh=False,
            )

    def test_force_refresh_falls_back_to_cache_on_backend_error(self):
        now = int(time.time())
        entry = self._cache_entry(
            backend_url="https://pro.example.com",
            cached_at=now - 20,
            exp=now + 3600,
            issued_at=now - 120,
            offline_grace_seconds=600,
        )
        campaigns_pro._write_lease_cache_file(os.environ["HP_PRO_LEASE_CACHE_PATH"], entry)

        with mock.patch("app.campaigns_pro.request_backend_lease", side_effect=campaigns_pro.CampaignProError("boom")):
            lease, source = campaigns_pro.get_backend_lease_cached(
                backend_url="https://pro.example.com",
                license_key="sk_test_123",
                app_id="noctisapi-pro",
                app_version="1.2.3",
                instance_id="instance-1",
                instance_fingerprint="f" * 64,
                force_refresh=True,
            )
        self.assertEqual(lease, entry["lease_jws"])
        self.assertEqual(source, "cache")


if __name__ == "__main__":
    unittest.main()
