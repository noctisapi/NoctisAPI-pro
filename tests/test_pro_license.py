import base64
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import license_runtime
from app import pro_license


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


def _signed_doc(*, private_key, payload: dict) -> dict:
    return {
        "schema_version": 1,
        "payload": payload,
        "signature": _sign_rsa(private_key, payload),
    }


class TestProLicenseOffline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_env = {k: os.environ.get(k) for k in (
            "HP_OFFLINE_LICENSE_PATH",
            "HP_OFFLINE_LICENSE_STATE_PATH",
            "HP_DEPLOYMENT_ID",
            "HP_LICENSE_STATUS_REFRESH_SECONDS",
            "HP_LICENSE_RUNTIME_CONFIG_PATH",
            "HP_LICENSE_PRODUCT",
        )}

        self.license_path = os.path.join(self._tmp.name, "license.json")
        self.state_path = os.path.join(self._tmp.name, "license_state.json")
        self.runtime_config_path = os.path.join(self._tmp.name, "license_runtime_overrides.json")
        os.environ["HP_OFFLINE_LICENSE_PATH"] = self.license_path
        os.environ["HP_OFFLINE_LICENSE_STATE_PATH"] = self.state_path
        os.environ["HP_LICENSE_RUNTIME_CONFIG_PATH"] = self.runtime_config_path
        os.environ["HP_DEPLOYMENT_ID"] = "dep-test-001"
        os.environ["HP_LICENSE_STATUS_REFRESH_SECONDS"] = "1"
        os.environ["HP_LICENSE_PRODUCT"] = "noctisapi"

        self.private_key, self.pub_pem = _gen_rsa_keypair()
        # Patch load_public_key_pem() in pro_license's namespace (imported name).
        self._patcher = patch(
            "app.pro_license.load_public_key_pem",
            return_value=self.pub_pem,
        )
        self._patcher.start()
        license_runtime.clear_overrides()
        pro_license.clear_cache()

    def tearDown(self):
        self._patcher.stop()
        pro_license.clear_cache()
        license_runtime.clear_overrides()
        self._tmp.cleanup()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _future_iso(self, seconds: int = 3600) -> str:
        dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write_license(self, *, license_version: int, expires_at: str) -> None:
        payload = {
            "license_id": "lic-test-1",
            "customer_email": "acct-1@example.com",
            "product": "noctisapi",
            "tier": "pro",
            "features": ["cases", "campaigns"],
            "license_version": int(license_version),
            "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expires_at,
            "machine_fingerprint": None,
            "limits": {"max_sensors": 5, "max_users": 1},
        }
        doc = _signed_doc(private_key=self.private_key, payload=payload)
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def _write_invalid_signature_license(self) -> None:
        payload = {
            "license_id": "lic-test-invalid-signature",
            "customer_email": "acct-1@example.com",
            "product": "noctisapi",
            "tier": "pro",
            "features": ["cases", "campaigns"],
            "license_version": 1,
            "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": self._future_iso(3600),
            "machine_fingerprint": None,
            "limits": {"max_sensors": 5, "max_users": 1},
        }
        doc = _signed_doc(private_key=self.private_key, payload=payload)
        doc["signature"] = "invalidsignatureXXXXXXXXXXXXXXXXXXXXXXXXX"
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def test_missing_license_is_core(self):
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertFalse(snap.get("pro_enabled"))
        self.assertFalse(snap.get("valid"))
        self.assertEqual(str(snap.get("source")), "offline_license")
        self.assertEqual(str(snap.get("reason_code")), "OFFLINE_LICENSE_MISSING")

    def test_valid_license_enables_pro(self):
        self._write_license(license_version=1, expires_at=self._future_iso(3600))
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertTrue(snap.get("valid"))
        self.assertTrue(snap.get("pro_enabled"))

    def test_public_key_missing_degrades_to_core(self):
        self._write_license(license_version=1, expires_at=self._future_iso(3600))
        self._patcher.stop()
        try:
            with patch(
                "app.pro_license.load_public_key_pem",
                side_effect=RuntimeError("key file not found"),
            ):
                pro_license.clear_cache()
                snap = pro_license.get_backend_license_snapshot(force_refresh=True)
                self.assertFalse(snap.get("valid"))
                self.assertFalse(snap.get("pro_enabled"))
                self.assertEqual(str(snap.get("reason_code")), "LICENSE_PUBLIC_KEY_MISSING")
        finally:
            self._patcher = patch(
                "honey_licensing.offline_license.load_public_key_pem",
                return_value=self.pub_pem,
            )
            self._patcher.start()

    def test_rollback_detected_for_older_generation(self):
        self._write_license(license_version=2, expires_at=self._future_iso(3600))
        first = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertTrue(first.get("valid"))

        self._write_license(license_version=1, expires_at=self._future_iso(3600))
        second = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertFalse(second.get("valid"))
        self.assertEqual(str(second.get("reason_code")), "ROLLBACK_DETECTED")

    def test_invalid_signature_falls_back_to_core(self):
        self._write_invalid_signature_license()
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertFalse(snap.get("valid"))
        self.assertFalse(snap.get("pro_enabled"))
        self.assertEqual(str(snap.get("reason_code")), "LICENSE_SIGNATURE_INVALID")

    def test_wrong_key_falls_back_to_core(self):
        self._write_license(license_version=1, expires_at=self._future_iso(3600))
        _, wrong_pub_pem = _gen_rsa_keypair()
        self._patcher.stop()
        try:
            with patch(
                "app.pro_license.load_public_key_pem",
                return_value=wrong_pub_pem,
            ):
                pro_license.clear_cache()
                snap = pro_license.get_backend_license_snapshot(force_refresh=True)
                self.assertFalse(snap.get("valid"))
                self.assertFalse(snap.get("pro_enabled"))
                self.assertEqual(str(snap.get("reason_code")), "LICENSE_SIGNATURE_INVALID")
        finally:
            self._patcher = patch(
                "honey_licensing.offline_license.load_public_key_pem",
                return_value=self.pub_pem,
            )
            self._patcher.start()


if __name__ == "__main__":
    unittest.main()
