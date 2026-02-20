import os
import time
import unittest
import tempfile
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from honey_licensing.client import (
    LicensingManager,
    LicensingStartupDenied,
    compute_client_identity,
    compute_instance_fingerprint_sha256_hex,
    get_or_create_uuid_file,
)


def _b64url(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _make_jws_rs256(payload: dict, private_key) -> str:
    import json

    header = {"alg": "RS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    p = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = (h + "." + p).encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    s = _b64url(sig)
    return h + "." + p + "." + s


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


class TestLicensingManager(unittest.TestCase):
    def _with_keypair(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv, pub_pem

    def _set_pinned_pubkey_path(self, pub_pem: bytes):
        old_path = os.environ.get("LICENSING_PINNED_PUBLIC_KEY_PATH")
        td = tempfile.TemporaryDirectory()
        pub_path = os.path.join(td.name, "licensing_server_public_key.pem")
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        os.environ["LICENSING_PINNED_PUBLIC_KEY_PATH"] = pub_path
        return td, old_path

    def test_startup_allow_enables_pro_when_enforced(self):
        priv, pub_pem = self._with_keypair()
        key_dir, old_path = self._set_pinned_pubkey_path(pub_pem)
        try:
            with tempfile.TemporaryDirectory() as td:
                licensing_url = "https://licensing.example.com"
                validate_url = licensing_url + "/v1/licenses/validate"

                def mock(url: str, payload: dict, timeout: float):
                    _ = timeout
                    if url != validate_url:
                        return 404, {"detail": "not found"}
                    signed = {
                        "request_nonce": payload["nonce"],
                        "request_timestamp": payload["timestamp"],
                        "valid": True,
                        "decision": "ALLOW",
                        "reason_code": "ok",
                        "expires_at": int(time.time()) + 3600,
                        "entitlements": {"plan": "pro"},
                        "recheck_after_seconds": 1,
                    }
                    return 200, {"server_signature": _make_jws_rs256(signed, priv)}

                mgr = LicensingManager(
                    licensing_url=licensing_url,
                    license_key="sk_live_test",
                    app_id="noctisapi-pro",
                    app_version="1.2.3",
                    instance_id_path=td + "/instance_id",
                    http_timeout_seconds=0.1,
                    min_recheck_seconds=1,
                    enforce_on_startup=True,
                    post_json_func=mock,
                )
                mgr.start()
                try:
                    self.assertTrue(mgr.is_pro_enabled())
                    st = mgr.get_state()
                    self.assertEqual(st.decision, "ALLOW")
                    self.assertTrue(st.valid)
                finally:
                    mgr.stop()
        finally:
            key_dir.cleanup()
            if old_path is None:
                os.environ.pop("LICENSING_PINNED_PUBLIC_KEY_PATH", None)
            else:
                os.environ["LICENSING_PINNED_PUBLIC_KEY_PATH"] = old_path

    def test_startup_deny_raises_when_enforced(self):
        priv, pub_pem = self._with_keypair()
        key_dir, old_path = self._set_pinned_pubkey_path(pub_pem)
        try:
            with tempfile.TemporaryDirectory() as td:
                licensing_url = "https://licensing.example.com"
                validate_url = licensing_url + "/v1/licenses/validate"

                def mock(url: str, payload: dict, timeout: float):
                    _ = timeout
                    if url != validate_url:
                        return 404, {"detail": "not found"}
                    signed = {
                        "request_nonce": payload["nonce"],
                        "request_timestamp": payload["timestamp"],
                        "valid": True,
                        "decision": "DENY",
                        "reason_code": "revoked",
                        "expires_at": int(time.time()) + 3600,
                        "entitlements": {},
                        "recheck_after_seconds": 1,
                    }
                    return 200, {"server_signature": _make_jws_rs256(signed, priv)}

                mgr = LicensingManager(
                    licensing_url=licensing_url,
                    license_key="sk_live_test",
                    app_id="noctisapi-pro",
                    app_version="1.2.3",
                    instance_id_path=td + "/instance_id",
                    http_timeout_seconds=0.1,
                    min_recheck_seconds=1,
                    enforce_on_startup=True,
                    post_json_func=mock,
                )
                with self.assertRaises(LicensingStartupDenied):
                    mgr.start()
        finally:
            key_dir.cleanup()
            if old_path is None:
                os.environ.pop("LICENSING_PINNED_PUBLIC_KEY_PATH", None)
            else:
                os.environ["LICENSING_PINNED_PUBLIC_KEY_PATH"] = old_path

    def test_nonce_mismatch_sets_invalid_state_when_not_enforced(self):
        priv, pub_pem = self._with_keypair()
        key_dir, old_path = self._set_pinned_pubkey_path(pub_pem)
        try:
            with tempfile.TemporaryDirectory() as td:
                licensing_url = "https://licensing.example.com"
                validate_url = licensing_url + "/v1/licenses/validate"

                def mock(url: str, payload: dict, timeout: float):
                    _ = timeout
                    if url != validate_url:
                        return 404, {"detail": "not found"}
                    signed = {
                        "request_nonce": "WRONG_NONCE",
                        "request_timestamp": payload["timestamp"],
                        "valid": True,
                        "decision": "ALLOW",
                        "reason_code": "ok",
                        "expires_at": int(time.time()) + 3600,
                        "entitlements": {},
                        "recheck_after_seconds": 1,
                    }
                    return 200, {"server_signature": _make_jws_rs256(signed, priv)}

                mgr = LicensingManager(
                    licensing_url=licensing_url,
                    license_key="sk_live_test",
                    app_id="noctisapi-pro",
                    app_version="1.2.3",
                    instance_id_path=td + "/instance_id",
                    http_timeout_seconds=0.1,
                    min_recheck_seconds=1,
                    enforce_on_startup=False,
                    post_json_func=mock,
                )
                mgr.start()
                try:
                    self.assertFalse(mgr.is_pro_enabled())
                    st = mgr.get_state()
                    self.assertFalse(st.valid)
                    self.assertEqual(st.last_error, "nonce_mismatch")
                finally:
                    mgr.stop()
        finally:
            key_dir.cleanup()
            if old_path is None:
                os.environ.pop("LICENSING_PINNED_PUBLIC_KEY_PATH", None)
            else:
                os.environ["LICENSING_PINNED_PUBLIC_KEY_PATH"] = old_path

    def test_403_with_signature_is_processed(self):
        priv, pub_pem = self._with_keypair()
        key_dir, old_path = self._set_pinned_pubkey_path(pub_pem)
        try:
            with tempfile.TemporaryDirectory() as td:
                licensing_url = "https://licensing.example.com"
                validate_url = licensing_url + "/v1/licenses/validate"

                def mock(url: str, payload: dict, timeout: float):
                    _ = timeout
                    if url != validate_url:
                        return 404, {"detail": "not found"}
                    signed = {
                        "request_nonce": payload["nonce"],
                        "request_timestamp": payload["timestamp"],
                        "valid": False,
                        "decision": "DENY",
                        "reason_code": "revoked",
                        "expires_at": int(time.time()) + 3600,
                        "entitlements": {},
                        "recheck_after_seconds": 1,
                    }
                    return 403, {"server_signature": _make_jws_rs256(signed, priv)}

                mgr = LicensingManager(
                    licensing_url=licensing_url,
                    license_key="sk_live_test",
                    app_id="noctisapi-pro",
                    app_version="1.2.3",
                    instance_id_path=td + "/instance_id",
                    http_timeout_seconds=0.1,
                    min_recheck_seconds=1,
                    enforce_on_startup=False,
                    post_json_func=mock,
                )
                mgr.start()
                try:
                    st = mgr.get_state()
                    self.assertEqual(st.decision, "DENY")
                    self.assertEqual(st.reason_code, "revoked")
                    self.assertIsNone(st.last_error)
                    self.assertFalse(mgr.is_pro_enabled())
                finally:
                    mgr.stop()
        finally:
            key_dir.cleanup()
            if old_path is None:
                os.environ.pop("LICENSING_PINNED_PUBLIC_KEY_PATH", None)
            else:
                os.environ["LICENSING_PINNED_PUBLIC_KEY_PATH"] = old_path

    def test_refresh_now_updates_state_immediately(self):
        priv, pub_pem = self._with_keypair()
        key_dir, old_path = self._set_pinned_pubkey_path(pub_pem)
        try:
            with tempfile.TemporaryDirectory() as td:
                licensing_url = "https://licensing.example.com"
                validate_url = licensing_url + "/v1/licenses/validate"
                calls = {"n": 0}

                def mock(url: str, payload: dict, timeout: float):
                    _ = timeout
                    if url != validate_url:
                        return 404, {"detail": "not found"}
                    calls["n"] += 1
                    signed = {
                        "request_nonce": payload["nonce"],
                        "request_timestamp": payload["timestamp"],
                        "valid": True,
                        "decision": "ALLOW",
                        "reason_code": "ok",
                        "expires_at": int(time.time()) + 3600,
                        "entitlements": {},
                        "recheck_after_seconds": 3600,
                    }
                    return 200, {"server_signature": _make_jws_rs256(signed, priv)}

                mgr = LicensingManager(
                    licensing_url=licensing_url,
                    license_key="sk_live_test",
                    app_id="noctisapi-pro",
                    app_version="1.2.3",
                    instance_id_path=td + "/instance_id",
                    http_timeout_seconds=0.1,
                    min_recheck_seconds=1000,
                    enforce_on_startup=False,
                    post_json_func=mock,
                )
                mgr.start()
                try:
                    first = calls["n"]
                    self.assertGreaterEqual(first, 1)
                    mgr.refresh_now()
                    self.assertGreaterEqual(calls["n"], first + 1)
                    self.assertTrue(mgr.is_pro_enabled())
                finally:
                    mgr.stop()
        finally:
            key_dir.cleanup()
            if old_path is None:
                os.environ.pop("LICENSING_PINNED_PUBLIC_KEY_PATH", None)
            else:
                os.environ["LICENSING_PINNED_PUBLIC_KEY_PATH"] = old_path


if __name__ == "__main__":
    unittest.main()
