"""
Tests for the schema_version=1 offline license format.

Covers:
  LicenseVerifier  — RSA signature verification, schema_version check
  LicenseValidator — product, tier, expiry, fingerprint validation
  LicenseStateResolver — rollback detection, state persistence
  resolve_local_license_state — end-to-end pipeline

All tests generate a temporary RSA key pair in-memory; no filesystem key required.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ── path setup ───────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from honey_licensing.offline_license import (
    LicenseLoader,
    LicenseStateResolver,
    LicenseValidator,
    LicenseVerifier,
    resolve_local_license_state,
)


# ── fixtures / helpers ────────────────────────────────────────────────────────

def _gen_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub, priv_pem, pub_pem


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sign(private_key, payload: dict) -> str:
    sig = private_key.sign(_canonical(payload), padding.PKCS1v15(), hashes.SHA256())
    return _b64url(sig)


def _future_iso(days: int = 30) -> str:
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _past_iso(days: int = 1) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_payload(
    *,
    product: str = "noctisapi",
    tier: str = "pro",
    expires_at: str | None = None,
    machine_fingerprint: str | None = None,
    license_id: str = "lic_test",
    license_version: int = 1,
    features: list[str] | None = None,
) -> dict:
    return {
        "license_id": license_id,
        "customer_email": "user@example.com",
        "product": product,
        "tier": tier,
        "features": features if features is not None else ["advanced_honeypots", "api_deception"],
        "license_version": license_version,
        "issued_at": "2026-03-11T18:00:00Z",
        "expires_at": expires_at if expires_at is not None else _future_iso(30),
        "machine_fingerprint": machine_fingerprint,
        "limits": {"max_sensors": 10, "max_users": 5},
    }


def _make_doc(private_key, payload: dict) -> dict:
    return {
        "schema_version": 1,
        "payload": payload,
        "signature": _sign(private_key, payload),
    }


@pytest.fixture(scope="module")
def rsa_keys():
    priv, pub, priv_pem, pub_pem = _gen_rsa_keypair()
    return {"priv": priv, "pub": pub, "priv_pem": priv_pem, "pub_pem": pub_pem}


# ── LicenseVerifier tests ─────────────────────────────────────────────────────

class TestLicenseVerifier:
    def test_valid_document_passes(self, rsa_keys):
        payload = _make_payload()
        doc = _make_doc(rsa_keys["priv"], payload)
        verifier = LicenseVerifier(public_key_pem=rsa_keys["pub_pem"])
        ok, verified_payload, reason = verifier.verify(doc)
        assert ok is True
        assert verified_payload == payload
        assert reason == "ok"

    def test_wrong_schema_version_rejected(self, rsa_keys):
        payload = _make_payload()
        doc = _make_doc(rsa_keys["priv"], payload)
        doc["schema_version"] = 2  # unsupported
        verifier = LicenseVerifier(public_key_pem=rsa_keys["pub_pem"])
        ok, _, reason = verifier.verify(doc)
        assert ok is False
        assert reason == "license_schema_version_unsupported"

    def test_missing_schema_version_rejected(self, rsa_keys):
        payload = _make_payload()
        doc = _make_doc(rsa_keys["priv"], payload)
        del doc["schema_version"]
        verifier = LicenseVerifier(public_key_pem=rsa_keys["pub_pem"])
        ok, _, reason = verifier.verify(doc)
        assert ok is False

    def test_tampered_payload_signature_invalid(self, rsa_keys):
        payload = _make_payload()
        doc = _make_doc(rsa_keys["priv"], payload)
        doc["payload"]["tier"] = "core"  # attacker tampers
        verifier = LicenseVerifier(public_key_pem=rsa_keys["pub_pem"])
        ok, _, reason = verifier.verify(doc)
        assert ok is False
        assert reason == "license_signature_invalid"

    def test_wrong_public_key_rejected(self, rsa_keys):
        # Sign with rsa_keys but verify with a different key
        _, _, _, wrong_pub_pem = _gen_rsa_keypair()
        payload = _make_payload()
        doc = _make_doc(rsa_keys["priv"], payload)
        verifier = LicenseVerifier(public_key_pem=wrong_pub_pem)
        ok, _, reason = verifier.verify(doc)
        assert ok is False
        assert reason == "license_signature_invalid"

    def test_missing_signature_field_rejected(self, rsa_keys):
        payload = _make_payload()
        doc = {"schema_version": 1, "payload": payload}  # no signature
        verifier = LicenseVerifier(public_key_pem=rsa_keys["pub_pem"])
        ok, _, reason = verifier.verify(doc)
        assert ok is False
        assert reason == "license_signature_missing"

    def test_signature_is_plain_string_not_dict(self, rsa_keys):
        payload = _make_payload()
        doc = _make_doc(rsa_keys["priv"], payload)
        # Old format had {"alg": "Ed25519", "kid": "...", "value": "..."}
        # New format must have a plain string
        assert isinstance(doc["signature"], str)

    def test_missing_payload_rejected(self, rsa_keys):
        doc = {"schema_version": 1, "signature": "abc"}
        verifier = LicenseVerifier(public_key_pem=rsa_keys["pub_pem"])
        ok, _, reason = verifier.verify(doc)
        assert ok is False
        assert reason == "license_json_invalid"


# ── LicenseValidator tests ────────────────────────────────────────────────────

class TestLicenseValidator:
    def test_valid_pro_payload(self):
        payload = _make_payload()
        validator = LicenseValidator(expected_product="noctisapi")
        ok, reason, details = validator.validate(payload)
        assert ok is True
        assert reason == "ok"

    def test_wrong_product_rejected(self):
        payload = _make_payload(product="other_product")
        validator = LicenseValidator(expected_product="noctisapi")
        ok, reason, _ = validator.validate(payload)
        assert ok is False
        assert reason == "license_product_mismatch"

    def test_product_check_is_case_insensitive(self):
        payload = _make_payload(product="NOCTISAPI")
        validator = LicenseValidator(expected_product="noctisapi")
        ok, reason, _ = validator.validate(payload)
        assert ok is True

    def test_expired_license_rejected(self):
        payload = _make_payload(expires_at=_past_iso(2))
        validator = LicenseValidator(expected_product="noctisapi")
        ok, reason, details = validator.validate(payload)
        assert ok is False
        assert reason == "license_expired"
        assert "expires_at" in details

    def test_no_expiry_is_valid(self):
        payload = _make_payload(expires_at=None)
        validator = LicenseValidator(expected_product="noctisapi")
        ok, reason, _ = validator.validate(payload)
        assert ok is True

    def test_unknown_tier_rejected(self):
        payload = _make_payload(tier="enterprise")
        validator = LicenseValidator(expected_product="noctisapi")
        ok, reason, _ = validator.validate(payload)
        assert ok is False
        assert reason == "license_tier_invalid"

    def test_core_tier_is_valid(self):
        payload = _make_payload(tier="core")
        validator = LicenseValidator(expected_product="noctisapi")
        ok, reason, _ = validator.validate(payload)
        assert ok is True

    def test_fingerprint_mismatch_rejected(self):
        payload = _make_payload(machine_fingerprint="fp_abc")
        validator = LicenseValidator(expected_product="noctisapi", instance_fingerprint="fp_xyz")
        ok, reason, _ = validator.validate(payload)
        assert ok is False
        assert reason == "license_fingerprint_mismatch"

    def test_fingerprint_match_passes(self):
        payload = _make_payload(machine_fingerprint="fp_abc")
        validator = LicenseValidator(expected_product="noctisapi", instance_fingerprint="fp_abc")
        ok, reason, _ = validator.validate(payload)
        assert ok is True

    def test_null_fingerprint_skips_check(self):
        payload = _make_payload(machine_fingerprint=None)
        # Even if no instance_fingerprint configured, null machine_fp should pass
        validator = LicenseValidator(expected_product="noctisapi", instance_fingerprint=None)
        ok, reason, _ = validator.validate(payload)
        assert ok is True

    def test_fingerprint_required_but_missing_instance_fp(self):
        payload = _make_payload(machine_fingerprint="fp_abc")
        validator = LicenseValidator(expected_product="noctisapi", instance_fingerprint=None)
        ok, reason, _ = validator.validate(payload)
        assert ok is False
        assert reason == "license_fingerprint_required"


# ── LicenseStateResolver tests ────────────────────────────────────────────────

class TestLicenseStateResolver:
    def test_valid_pro_payload_returns_allow(self, tmp_path):
        payload = _make_payload(tier="pro", license_version=1)
        state_path = str(tmp_path / "state.json")
        resolver = LicenseStateResolver(state_path=state_path, runtime_deployment_id=None)
        decision = resolver.resolve(
            payload=payload, validation_ok=True, validation_reason="ok", details={}
        )
        assert decision.valid is True
        assert decision.decision == "ALLOW"
        assert decision.tier == "pro"
        assert "advanced_honeypots" in decision.features

    def test_core_tier_returns_limited(self, tmp_path):
        payload = _make_payload(tier="core", license_version=1)
        state_path = str(tmp_path / "state.json")
        resolver = LicenseStateResolver(state_path=state_path, runtime_deployment_id=None)
        decision = resolver.resolve(
            payload=payload, validation_ok=True, validation_reason="ok", details={}
        )
        assert decision.valid is False
        assert decision.decision == "LIMITED"
        assert decision.tier == "core"

    def test_validation_failure_returns_limited(self, tmp_path):
        payload = _make_payload(tier="pro")
        state_path = str(tmp_path / "state.json")
        resolver = LicenseStateResolver(state_path=state_path, runtime_deployment_id=None)
        decision = resolver.resolve(
            payload=payload, validation_ok=False, validation_reason="license_expired", details={}
        )
        assert decision.valid is False
        assert decision.reason_code == "LICENSE_EXPIRED"

    def test_rollback_detected(self, tmp_path):
        payload_v3 = _make_payload(tier="pro", license_version=3)
        payload_v2 = _make_payload(tier="pro", license_version=2)
        state_path = str(tmp_path / "state.json")
        resolver = LicenseStateResolver(state_path=state_path, runtime_deployment_id=None)
        # Advance to v3
        resolver.resolve(payload=payload_v3, validation_ok=True, validation_reason="ok", details={})
        # Try to use v2 (rollback)
        decision = resolver.resolve(payload=payload_v2, validation_ok=True, validation_reason="ok", details={})
        assert decision.valid is False
        assert decision.reason_code == "ROLLBACK_DETECTED"

    def test_license_version_maps_to_license_generation_field(self, tmp_path):
        payload = _make_payload(license_version=7)
        state_path = str(tmp_path / "state.json")
        resolver = LicenseStateResolver(state_path=state_path, runtime_deployment_id=None)
        decision = resolver.resolve(
            payload=payload, validation_ok=True, validation_reason="ok", details={}
        )
        assert decision.license_generation == 7

    def test_machine_fingerprint_becomes_deployment_id(self, tmp_path):
        payload = _make_payload(machine_fingerprint="fp_machine_001")
        state_path = str(tmp_path / "state.json")
        resolver = LicenseStateResolver(state_path=state_path, runtime_deployment_id=None)
        decision = resolver.resolve(
            payload=payload, validation_ok=True, validation_reason="ok", details={}
        )
        assert decision.deployment_id == "fp_machine_001"


# ── resolve_local_license_state end-to-end tests ─────────────────────────────

class TestResolveLocalLicenseStatePipeline:
    def _write_license(self, path: str, doc: dict) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_valid_pro_license_returns_allow(self, rsa_keys, tmp_path):
        license_path = str(tmp_path / "license.json")
        state_path = str(tmp_path / "state.json")
        payload = _make_payload(tier="pro", expires_at=_future_iso(30))
        doc = _make_doc(rsa_keys["priv"], payload)
        self._write_license(license_path, doc)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )
        assert decision.valid is True
        assert decision.decision == "ALLOW"
        assert decision.tier == "pro"
        assert decision.reason_code == "OK"

    def test_missing_license_file_returns_limited(self, rsa_keys, tmp_path):
        decision = resolve_local_license_state(
            license_path=str(tmp_path / "nonexistent.json"),
            state_path=str(tmp_path / "state.json"),
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )
        assert decision.valid is False
        assert decision.reason_code == "OFFLINE_LICENSE_MISSING"

    def test_invalid_signature_returns_limited(self, rsa_keys, tmp_path):
        license_path = str(tmp_path / "license.json")
        state_path = str(tmp_path / "state.json")
        payload = _make_payload(tier="pro")
        doc = _make_doc(rsa_keys["priv"], payload)
        doc["payload"]["tier"] = "core"  # tamper after signing
        self._write_license(license_path, doc)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )
        assert decision.valid is False
        assert decision.reason_code == "LICENSE_SIGNATURE_INVALID"

    def test_expired_license_returns_limited(self, rsa_keys, tmp_path):
        license_path = str(tmp_path / "license.json")
        state_path = str(tmp_path / "state.json")
        payload = _make_payload(tier="pro", expires_at=_past_iso(2))
        doc = _make_doc(rsa_keys["priv"], payload)
        self._write_license(license_path, doc)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )
        assert decision.valid is False
        assert decision.reason_code == "LICENSE_EXPIRED"

    def test_wrong_product_returns_limited(self, rsa_keys, tmp_path):
        license_path = str(tmp_path / "license.json")
        state_path = str(tmp_path / "state.json")
        payload = _make_payload(product="other_app", tier="pro")
        doc = _make_doc(rsa_keys["priv"], payload)
        self._write_license(license_path, doc)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )
        assert decision.valid is False
        assert decision.reason_code == "LICENSE_PRODUCT_MISMATCH"

    def test_fingerprint_mismatch_returns_limited(self, rsa_keys, tmp_path):
        license_path = str(tmp_path / "license.json")
        state_path = str(tmp_path / "state.json")
        payload = _make_payload(tier="pro", machine_fingerprint="fp_server_001")
        doc = _make_doc(rsa_keys["priv"], payload)
        self._write_license(license_path, doc)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
            instance_fingerprint="fp_wrong_machine",
        )
        assert decision.valid is False
        assert decision.reason_code == "LICENSE_FINGERPRINT_MISMATCH"

    def test_fingerprint_match_passes(self, rsa_keys, tmp_path):
        license_path = str(tmp_path / "license.json")
        state_path = str(tmp_path / "state.json")
        payload = _make_payload(tier="pro", machine_fingerprint="fp_server_001")
        doc = _make_doc(rsa_keys["priv"], payload)
        self._write_license(license_path, doc)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
            instance_fingerprint="fp_server_001",
        )
        assert decision.valid is True
        assert decision.reason_code == "OK"

    def test_wrong_schema_version_returns_limited(self, rsa_keys, tmp_path):
        license_path = str(tmp_path / "license.json")
        state_path = str(tmp_path / "state.json")
        payload = _make_payload(tier="pro")
        doc = _make_doc(rsa_keys["priv"], payload)
        doc["schema_version"] = 99
        self._write_license(license_path, doc)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=state_path,
            runtime_deployment_id=None,
            public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )
        assert decision.valid is False
        assert decision.reason_code == "LICENSE_SCHEMA_VERSION_UNSUPPORTED"

    def test_rollback_detected_across_calls(self, rsa_keys, tmp_path):
        state_path = str(tmp_path / "state.json")

        # First call with v3
        license_path = str(tmp_path / "license.json")
        payload_v3 = _make_payload(tier="pro", license_version=3)
        self._write_license(license_path, _make_doc(rsa_keys["priv"], payload_v3))
        resolve_local_license_state(
            license_path=license_path, state_path=state_path,
            runtime_deployment_id=None, public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )

        # Second call with v2 (rollback attempt)
        payload_v2 = _make_payload(tier="pro", license_version=2)
        self._write_license(license_path, _make_doc(rsa_keys["priv"], payload_v2))
        decision = resolve_local_license_state(
            license_path=license_path, state_path=state_path,
            runtime_deployment_id=None, public_key_pem=rsa_keys["pub_pem"],
            expected_product="noctisapi",
        )
        assert decision.valid is False
        assert decision.reason_code == "ROLLBACK_DETECTED"

    def test_invalid_public_key_pem_returns_limited(self, tmp_path):
        license_path = str(tmp_path / "license.json")
        with open(license_path, "w") as f:
            json.dump({"schema_version": 1, "payload": {}, "signature": "abc"}, f)

        decision = resolve_local_license_state(
            license_path=license_path,
            state_path=str(tmp_path / "state.json"),
            runtime_deployment_id=None,
            public_key_pem=b"not-a-real-pem",
            expected_product="noctisapi",
        )
        assert decision.valid is False
        assert decision.reason_code == "LICENSE_PUBLIC_KEY_INVALID"
