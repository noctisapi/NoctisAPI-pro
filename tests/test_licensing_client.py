import base64
import json
import os
import tempfile
import time
import unittest
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from honey_licensing.client import (
    LicensingManager,
    LicensingStartupDenied,
    compute_client_identity,
    compute_instance_fingerprint_sha256_hex,
    get_or_create_uuid_file,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _make_signed_license_document(*, private_key: Ed25519PrivateKey, kid: str, payload: dict) -> dict:
    sig = private_key.sign(_canonical_json_bytes(payload))
    return {
        "schema": "license.json/v2",
        "payload": payload,
        "signature": {
            "alg": "Ed25519",
            "kid": kid,
            "value": _b64url(sig),
        },
    }


class TestUUIDFile(unittest.TestCase):
    def test_get_or_create_uuid_file_persists(self):
        with tempfile.TemporaryDirectory() as td:
            p = td + "/instance_id"
            a = get_or_create_uuid_file(p)
            b = get_or_create_uuid_file(p)
            self.assertEqual(a, b)
            UUID(a)


class TestFingerprint(unittest.TestCase):
    def test_compute_instance_fingerprint_sha256_hex_returns_64_hex(self):
        fp = compute_instance_fingerprint_sha256_hex()
        self.assertEqual(len(fp), 64)
        int(fp, 16)

    def test_fingerprint_env_override_is_used(self):
        old = os.environ.get("INSTANCE_FINGERPRINT_SHA256")
        try:
            os.environ["INSTANCE_FINGERPRINT_SHA256"] = "a" * 64
            fp = compute_instance_fingerprint_sha256_hex()
            self.assertEqual(fp, "a" * 64)
        finally:
            if old is None:
                os.environ.pop("INSTANCE_FINGERPRINT_SHA256", None)
            else:
                os.environ["INSTANCE_FINGERPRINT_SHA256"] = old

    def test_compute_client_identity_returns_expected_shape(self):
        ident = compute_client_identity()
        self.assertIn("instance_id", ident)
        self.assertIn("instance_id_path", ident)
        self.assertIn("instance_fingerprint_sha256", ident)
        self.assertEqual(len(ident["instance_fingerprint_sha256"]), 64)
        int(ident["instance_fingerprint_sha256"], 16)


class TestLicensingManagerOffline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_env = {k: os.environ.get(k) for k in (
            "HP_OFFLINE_LICENSE_PATH",
            "HP_OFFLINE_LICENSE_STATE_PATH",
            "HP_OFFLINE_PUBLIC_KEYS_JSON",
            "HP_DEPLOYMENT_ID",
            "INSTANCE_ID_PATH",
            "HP_ENFORCE_LICENSE",
        )}

        self.license_path = os.path.join(self._tmp.name, "license.json")
        self.state_path = os.path.join(self._tmp.name, "license_state.json")
        self.instance_id_path = os.path.join(self._tmp.name, "instance_id")
        self.deployment_id = get_or_create_uuid_file(self.instance_id_path)

        os.environ["HP_OFFLINE_LICENSE_PATH"] = self.license_path
        os.environ["HP_OFFLINE_LICENSE_STATE_PATH"] = self.state_path
        os.environ["INSTANCE_ID_PATH"] = self.instance_id_path
        os.environ["HP_DEPLOYMENT_ID"] = self.deployment_id
        os.environ["HP_ENFORCE_LICENSE"] = "0"

        self.private_key = Ed25519PrivateKey.generate()
        self.kid = "test-ed25519-1"
        pub_raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        os.environ["HP_OFFLINE_PUBLIC_KEYS_JSON"] = json.dumps({self.kid: _b64url(pub_raw)})

    def tearDown(self):
        self._tmp.cleanup()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _write_license(self, *, expires_at: int) -> None:
        payload = {
            "schema_version": 2,
            "license_id": "lic-test-1",
            "account_id": "acct-1",
            "plan": "pro",
            "tier": "pro",
            "status": "active",
            "issued_at": int(time.time()),
            "expires_at": int(expires_at),
            "features": ["campaigns", "cases"],
            "entitlements": ["pro", "campaigns", "cases"],
            "license_generation": 1,
            "deployment_binding": {
                "mode": "soft",
                "deployment_id": self.deployment_id,
            },
            "offline_policy": {
                "offline_grace_seconds": 60,
                "fallback_tier": "core",
            },
        }
        doc = _make_signed_license_document(private_key=self.private_key, kid=self.kid, payload=payload)
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def test_startup_denied_when_enforced_and_missing_license(self):
        os.environ["HP_ENFORCE_LICENSE"] = "1"
        mgr = LicensingManager.from_env()
        with self.assertRaises(LicensingStartupDenied):
            mgr.start()

    def test_startup_allow_with_valid_signed_license(self):
        self._write_license(expires_at=int(time.time()) + 3600)
        mgr = LicensingManager.from_env()
        mgr.start()
        try:
            self.assertTrue(mgr.is_pro_enabled())
            st = mgr.get_state()
            self.assertTrue(st.valid)
            self.assertEqual(st.decision, "ALLOW")
            self.assertEqual(st.reason_code, "OK")
        finally:
            mgr.stop()

    def test_expired_license_falls_back_to_core(self):
        self._write_license(expires_at=int(time.time()) - 3600)
        mgr = LicensingManager.from_env()
        st = mgr.refresh_now()
        self.assertFalse(st.valid)
        self.assertIn("LICENSE_EXPIRED", str(st.reason_code or ""))
        self.assertFalse(mgr.is_pro_enabled())


if __name__ == "__main__":
    unittest.main()
