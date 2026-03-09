import base64
import json
import os
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import license_runtime
from app import pro_license


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _signed_doc(*, private_key: Ed25519PrivateKey, kid: str, payload: dict) -> dict:
    sig = private_key.sign(_canonical_json_bytes(payload))
    return {
        "schema": "license.json/v2",
        "payload": payload,
        "signature": {"alg": "Ed25519", "kid": kid, "value": _b64url(sig)},
    }


class TestProLicenseOffline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_env = {k: os.environ.get(k) for k in (
            "HP_OFFLINE_LICENSE_PATH",
            "HP_OFFLINE_LICENSE_STATE_PATH",
            "HP_OFFLINE_PUBLIC_KEYS_JSON",
            "HP_OFFLINE_PUBLIC_KEYS_BUNDLE_PATH",
            "HP_DEPLOYMENT_ID",
            "HP_LICENSE_STATUS_REFRESH_SECONDS",
            "HP_LICENSE_RUNTIME_CONFIG_PATH",
        )}

        self.license_path = os.path.join(self._tmp.name, "license.json")
        self.state_path = os.path.join(self._tmp.name, "license_state.json")
        self.runtime_config_path = os.path.join(self._tmp.name, "license_runtime_overrides.json")
        os.environ["HP_OFFLINE_LICENSE_PATH"] = self.license_path
        os.environ["HP_OFFLINE_LICENSE_STATE_PATH"] = self.state_path
        os.environ["HP_LICENSE_RUNTIME_CONFIG_PATH"] = self.runtime_config_path
        os.environ["HP_DEPLOYMENT_ID"] = "dep-test-001"
        os.environ["HP_LICENSE_STATUS_REFRESH_SECONDS"] = "1"

        self.private_key = Ed25519PrivateKey.generate()
        self.kid = "test-ed25519-1"
        pub_raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        os.environ["HP_OFFLINE_PUBLIC_KEYS_JSON"] = json.dumps({self.kid: _b64url(pub_raw)})
        license_runtime.clear_overrides()
        pro_license.clear_cache()

    def tearDown(self):
        pro_license.clear_cache()
        license_runtime.clear_overrides()
        self._tmp.cleanup()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _write_license(self, *, generation: int, expires_at: int) -> None:
        payload = {
            "schema_version": 2,
            "license_id": "lic-test-1",
            "account_id": "acct-1",
            "plan": "pro",
            "tier": "pro",
            "status": "active",
            "issued_at": int(time.time()),
            "expires_at": int(expires_at),
            "features": ["cases", "campaigns"],
            "entitlements": ["pro", "cases", "campaigns"],
            "license_generation": int(generation),
            "deployment_binding": {
                "mode": "soft",
                "deployment_id": "dep-test-001",
            },
            "offline_policy": {
                "offline_grace_seconds": 60,
                "fallback_tier": "core",
            },
        }
        doc = _signed_doc(private_key=self.private_key, kid=self.kid, payload=payload)
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def _write_invalid_signature_license(self) -> None:
        payload = {
            "schema_version": 2,
            "license_id": "lic-test-invalid-signature",
            "account_id": "acct-1",
            "plan": "pro",
            "tier": "pro",
            "status": "active",
            "issued_at": int(time.time()),
            "expires_at": int(time.time()) + 3600,
            "features": ["cases", "campaigns"],
            "entitlements": ["pro", "cases", "campaigns"],
            "license_generation": 1,
            "deployment_binding": {
                "mode": "soft",
                "deployment_id": "dep-test-001",
            },
            "offline_policy": {
                "offline_grace_seconds": 60,
                "fallback_tier": "core",
            },
        }
        doc = _signed_doc(private_key=self.private_key, kid=self.kid, payload=payload)
        doc["signature"]["value"] = "invalid-signature"
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def test_missing_license_is_core(self):
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertFalse(snap.get("pro_enabled"))
        self.assertFalse(snap.get("valid"))
        self.assertEqual(str(snap.get("source")), "offline_license")
        self.assertEqual(str(snap.get("reason_code")), "OFFLINE_LICENSE_MISSING")

    def test_valid_license_enables_pro(self):
        self._write_license(generation=1, expires_at=int(time.time()) + 3600)
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertTrue(snap.get("valid"))
        self.assertTrue(snap.get("pro_enabled"))

    def test_bundled_public_keys_path_is_used(self):
        self._write_license(generation=1, expires_at=int(time.time()) + 3600)
        os.environ.pop("HP_OFFLINE_PUBLIC_KEYS_JSON", None)
        pub_raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        bundle_path = os.path.join(self._tmp.name, "offline_public_keys.json")
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump({self.kid: _b64url(pub_raw)}, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        os.environ["HP_OFFLINE_PUBLIC_KEYS_BUNDLE_PATH"] = bundle_path
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertTrue(snap.get("valid"))
        self.assertTrue(snap.get("pro_enabled"))
        self.assertEqual(str((snap.get("entitlements") or {}).get("tier")), "pro")

    def test_rollback_detected_for_older_generation(self):
        self._write_license(generation=2, expires_at=int(time.time()) + 3600)
        first = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertTrue(first.get("valid"))

        self._write_license(generation=1, expires_at=int(time.time()) + 3600)
        second = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertFalse(second.get("valid"))
        self.assertEqual(str(second.get("reason_code")), "ROLLBACK_DETECTED")

    def test_invalid_signature_falls_back_to_core(self):
        self._write_invalid_signature_license()
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertFalse(snap.get("valid"))
        self.assertFalse(snap.get("pro_enabled"))
        self.assertEqual(str(snap.get("reason_code")), "LICENSE_SIGNATURE_INVALID")

    def test_public_keys_json_override_is_used_for_validation(self):
        self._write_license(generation=1, expires_at=int(time.time()) + 3600)
        os.environ.pop("HP_OFFLINE_PUBLIC_KEYS_JSON", None)
        pub_raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        license_runtime.save_overrides(
            updates={"HP_OFFLINE_PUBLIC_KEYS_JSON": json.dumps({self.kid: _b64url(pub_raw)})},
            clear_all=False,
        )
        snap = pro_license.get_backend_license_snapshot(force_refresh=True)
        self.assertTrue(snap.get("valid"))
        self.assertTrue(snap.get("pro_enabled"))


if __name__ == "__main__":
    unittest.main()
