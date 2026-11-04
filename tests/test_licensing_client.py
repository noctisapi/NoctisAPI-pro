import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64

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


def _gen_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _sign_rsa(private_key, payload: dict) -> str:
    sig = private_key.sign(_canonical_json_bytes(payload), padding.PKCS1v15(), hashes.SHA256())
    return _b64url(sig)


def _make_doc(private_key, payload: dict) -> dict:
    return {"schema_version": 1, "payload": payload, "signature": _sign_rsa(private_key, payload)}


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

        self.private_key, self.pub_pem = _gen_rsa_keypair()
        # Patch load_public_key_pem() in client's namespace (imported name).
        self._patcher = patch(
            "honey_licensing.client.load_public_key_pem",
            return_value=self.pub_pem,
        )
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        self._tmp.cleanup()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _future_iso(self, seconds: int = 3600) -> str:
        dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write_license(self, *, expires_at: str) -> None:
        payload = {
            "license_id": "lic-test-1",
            "customer_email": "test@example.com",
            "product": "noctisapi",
            "tier": "pro",
            "features": ["campaigns", "cases"],
            "license_version": 1,
            "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expires_at,
            "machine_fingerprint": None,
            "limits": {"max_sensors": 5, "max_users": 1},
        }
        doc = _make_doc(self.private_key, payload)
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def test_startup_denied_when_enforced_and_missing_license(self):
        os.environ["HP_ENFORCE_LICENSE"] = "1"
        mgr = LicensingManager.from_env()
        with self.assertRaises(LicensingStartupDenied):
            mgr.start()

    def test_startup_allow_with_valid_signed_license(self):
        self._write_license(expires_at=self._future_iso(3600))
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
        self._write_license(expires_at=self._future_iso(-3600))
        mgr = LicensingManager.from_env()
        st = mgr.refresh_now()
        self.assertFalse(st.valid)
        self.assertIn("LICENSE_EXPIRED", str(st.reason_code or ""))
        self.assertFalse(mgr.is_pro_enabled())


if __name__ == "__main__":
    unittest.main()
