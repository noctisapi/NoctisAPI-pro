import os
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import campaigns_pro
from honey_licensing.feature_flags import enabled_features, set_pro_enabled_provider


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _make_jws_rs256(payload: dict, private_key) -> str:
    import json

    header = {"alg": "RS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    p = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = (h + "." + p).encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    s = _b64url(sig)
    return h + "." + p + "." + s


class TestCampaignResultVerification(unittest.TestCase):
    def setUp(self):
        self._old_pub_path = os.environ.get("PRO_RESULTS_PUBLIC_KEY_PATH")
        self._old_env = os.environ.get("APP_ENV")

    def tearDown(self):
        if self._old_pub_path is None:
            os.environ.pop("PRO_RESULTS_PUBLIC_KEY_PATH", None)
        else:
            os.environ["PRO_RESULTS_PUBLIC_KEY_PATH"] = self._old_pub_path
        if self._old_env is None:
            os.environ.pop("APP_ENV", None)
        else:
            os.environ["APP_ENV"] = self._old_env

    def _with_keypair(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv, pub_pem

    def test_verify_signed_campaign_result_accepts_valid_payload(self):
        priv, pub_pem = self._with_keypair()
        result = {"campaigns": [{"campaign_id": "abc"}], "links": [], "metrics": {"duration_ms": 1}}
        snapshot_hash = "a" * 64
        app_id = "shadowapi-pro"
        instance_id = "instance-1"
        license_key_hash = "b" * 64
        exp = int(time.time()) + 120
        payload = {
            "op": "campaigns_recompute",
            "app_id": app_id,
            "instance_id": instance_id,
            "license_key_hash": license_key_hash,
            "snapshot_hash": snapshot_hash,
            "result_hash": campaigns_pro.sha256_hex_obj(result),
            "exp": exp,
            "expires_at": exp,
        }
        sig = _make_jws_rs256(payload, priv)

        with tempfile.TemporaryDirectory() as td:
            pub_path = os.path.join(td, "pub.pem")
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
            os.environ["PRO_RESULTS_PUBLIC_KEY_PATH"] = pub_path
            os.environ["APP_ENV"] = "dev"

            verified_result, verified_payload, verified_exp = campaigns_pro.verify_signed_campaign_result(
                data={"result": result, "result_sig": sig, "expires_at": exp},
                expected_snapshot_hash=snapshot_hash,
                expected_app_id=app_id,
                expected_instance_id=instance_id,
                expected_license_key_hash=license_key_hash,
            )
            self.assertEqual(verified_result, result)
            self.assertEqual(verified_payload["op"], "campaigns_recompute")
            self.assertEqual(verified_exp, exp)

    def test_verify_signed_campaign_result_rejects_result_hash_mismatch(self):
        priv, pub_pem = self._with_keypair()
        base_result = {"campaigns": [{"campaign_id": "abc"}], "links": [], "metrics": {}}
        tampered_result = {"campaigns": [{"campaign_id": "xyz"}], "links": [], "metrics": {}}
        snapshot_hash = "a" * 64
        app_id = "shadowapi-pro"
        instance_id = "instance-1"
        exp = int(time.time()) + 120
        payload = {
            "op": "campaigns_recompute",
            "app_id": app_id,
            "instance_id": instance_id,
            "snapshot_hash": snapshot_hash,
            "result_hash": campaigns_pro.sha256_hex_obj(base_result),
            "exp": exp,
            "expires_at": exp,
        }
        sig = _make_jws_rs256(payload, priv)

        with tempfile.TemporaryDirectory() as td:
            pub_path = os.path.join(td, "pub.pem")
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
            os.environ["PRO_RESULTS_PUBLIC_KEY_PATH"] = pub_path
            os.environ["APP_ENV"] = "dev"

            with self.assertRaises(campaigns_pro.CampaignProError):
                campaigns_pro.verify_signed_campaign_result(
                    data={"result": tampered_result, "result_sig": sig, "expires_at": exp},
                    expected_snapshot_hash=snapshot_hash,
                    expected_app_id=app_id,
                    expected_instance_id=instance_id,
                    expected_license_key_hash="",
                )

    def test_verify_signed_campaign_result_rejects_expired_signature(self):
        priv, pub_pem = self._with_keypair()
        result = {"campaigns": [], "links": [], "metrics": {}}
        snapshot_hash = "a" * 64
        app_id = "shadowapi-pro"
        instance_id = "instance-1"
        exp = int(time.time()) - 10
        payload = {
            "op": "campaigns_recompute",
            "app_id": app_id,
            "instance_id": instance_id,
            "snapshot_hash": snapshot_hash,
            "result_hash": campaigns_pro.sha256_hex_obj(result),
            "exp": exp,
            "expires_at": exp,
        }
        sig = _make_jws_rs256(payload, priv)

        with tempfile.TemporaryDirectory() as td:
            pub_path = os.path.join(td, "pub.pem")
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
            os.environ["PRO_RESULTS_PUBLIC_KEY_PATH"] = pub_path
            os.environ["APP_ENV"] = "dev"

            with self.assertRaises(campaigns_pro.CampaignProError):
                campaigns_pro.verify_signed_campaign_result(
                    data={"result": result, "result_sig": sig, "expires_at": exp},
                    expected_snapshot_hash=snapshot_hash,
                    expected_app_id=app_id,
                    expected_instance_id=instance_id,
                    expected_license_key_hash="",
                )


class TestFeatureFlagsCampaigns(unittest.TestCase):
    def setUp(self):
        set_pro_enabled_provider(None)

    def tearDown(self):
        set_pro_enabled_provider(None)

    def test_without_runtime_provider_no_pro_features_are_enabled(self):
        features = enabled_features()
        self.assertEqual(features, set())

    def test_runtime_provider_controls_pro_features(self):
        set_pro_enabled_provider(lambda: True)
        features = enabled_features()
        self.assertIn("campaigns", features)
        self.assertIn("cases", features)


if __name__ == "__main__":
    unittest.main()
