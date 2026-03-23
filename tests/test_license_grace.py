"""
Tests for offline grace period support in honey_licensing.offline_license.

Covers:
  LicenseValidator  — grace_seconds in payload, boundary conditions
  LicenseStateResolver — GRACE decision propagation
  resolve_local_license_state — end-to-end with grace
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from honey_licensing.offline_license import (
    LicenseStateResolver,
    LicenseValidator,
    LicenseVerifier,
    LocalLicenseDecision,
    resolve_local_license_state,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _gen_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return priv, priv_pem, pub_pem


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign(priv, payload: dict) -> str:
    sig = priv.sign(_canonical(payload), padding.PKCS1v15(), hashes.SHA256())
    raw = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return raw.decode("ascii")


def _make_doc(priv, payload: dict) -> dict:
    return {"schema_version": 1, "payload": payload, "signature": _sign(priv, payload)}


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _make_payload(*, expires_delta: int, grace_seconds: int = 0, tier: str = "pro") -> dict:
    """Build a payload where expires_at = now + expires_delta (negative = already expired)."""
    exp_epoch = _now() + expires_delta
    exp_iso = datetime.fromtimestamp(exp_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    p: dict = {
        "license_id": "lic-test",
        "product": "noctisapi",
        "tier": tier,
        "features": ["cases"],
        "license_version": 1,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": exp_iso,
        "machine_fingerprint": None,
    }
    if grace_seconds:
        p["grace_seconds"] = grace_seconds
    return p


# ── LicenseValidator grace tests ─────────────────────────────────────────────

class TestLicenseValidatorGrace:
    def setup_method(self):
        self.v = LicenseValidator(expected_product="noctisapi")

    def test_valid_not_expired(self):
        payload = _make_payload(expires_delta=3600)
        ok, reason, details = self.v.validate(payload)
        assert ok is True
        assert reason == "ok"
        assert "grace_until" not in details

    def test_expired_no_grace_seconds(self):
        payload = _make_payload(expires_delta=-100)
        ok, reason, details = self.v.validate(payload)
        assert ok is False
        assert reason == "license_expired"

    def test_expired_with_grace_still_in_window(self):
        # expired 1 hour ago, grace = 7 days
        payload = _make_payload(expires_delta=-3600, grace_seconds=604800)
        ok, reason, details = self.v.validate(payload)
        assert ok is True
        assert reason == "grace"
        assert "grace_until" in details
        assert details["grace_until"] > _now()

    def test_expired_grace_also_expired(self):
        # expired 8 days ago, grace = 7 days → fully expired
        payload = _make_payload(expires_delta=-(8 * 86400), grace_seconds=7 * 86400)
        ok, reason, details = self.v.validate(payload)
        assert ok is False
        assert reason == "license_expired"

    def test_grace_boundary_exactly_at_expires_at(self):
        # expires_at = now - 1s, grace = 10s → should be in grace
        payload = _make_payload(expires_delta=-1, grace_seconds=10)
        ok, reason, _ = self.v.validate(payload)
        assert ok is True
        assert reason == "grace"

    def test_grace_zero_means_no_grace(self):
        payload = _make_payload(expires_delta=-100, grace_seconds=0)
        ok, reason, _ = self.v.validate(payload)
        assert ok is False
        assert reason == "license_expired"

    def test_no_expiry_field_always_valid(self):
        payload = {
            "license_id": "lic-x",
            "product": "noctisapi",
            "tier": "pro",
            "features": [],
            "license_version": 1,
            "issued_at": "2026-01-01T00:00:00Z",
            "machine_fingerprint": None,
        }
        ok, reason, _ = self.v.validate(payload)
        assert ok is True
        assert reason == "ok"


# ── LicenseStateResolver GRACE decision ──────────────────────────────────────

class TestLicenseStateResolverGrace:
    def setup_method(self):
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")

    def _resolver(self):
        return LicenseStateResolver(state_path=self.state_path, runtime_deployment_id=None)

    def test_grace_returns_grace_decision(self):
        payload = _make_payload(expires_delta=-3600, grace_seconds=604800)
        resolver = self._resolver()
        decision = resolver.resolve(
            payload=payload,
            validation_ok=True,
            validation_reason="grace",
            details={"expires_at": _now() - 3600, "grace_until": _now() + 601200},
        )
        assert decision.valid is True
        assert decision.tier == "pro"
        assert decision.decision == "GRACE"
        assert decision.reason_code == "GRACE"
        assert decision.in_grace is True
        assert decision.grace_until is not None
        assert decision.grace_until > _now()

    def test_allow_decision_when_not_in_grace(self):
        payload = _make_payload(expires_delta=3600)
        resolver = self._resolver()
        decision = resolver.resolve(
            payload=payload,
            validation_ok=True,
            validation_reason="ok",
            details={"expires_at": _now() + 3600},
        )
        assert decision.decision == "ALLOW"
        assert decision.in_grace is False
        assert decision.grace_until is None

    def test_limited_when_expired_beyond_grace(self):
        payload = _make_payload(expires_delta=-(8 * 86400), grace_seconds=7 * 86400)
        resolver = self._resolver()
        decision = resolver.resolve(
            payload=payload,
            validation_ok=False,
            validation_reason="license_expired",
            details={"expires_at": _now() - 8 * 86400},
        )
        assert decision.valid is False
        assert decision.decision == "LIMITED"
        assert decision.tier == "core"
        assert decision.in_grace is False


# ── End-to-end: resolve_local_license_state with grace ───────────────────────

class TestEndToEndGrace:
    def setup_method(self):
        self.priv, self.priv_pem, self.pub_pem = _gen_rsa_keypair()
        self.tmp = tempfile.mkdtemp()
        self.license_path = os.path.join(self.tmp, "license.json")
        self.state_path = os.path.join(self.tmp, "state.json")

    def _write_license(self, payload: dict):
        doc = _make_doc(self.priv, payload)
        with open(self.license_path, "w") as f:
            json.dump(doc, f)

    def _resolve(self):
        return resolve_local_license_state(
            license_path=self.license_path,
            state_path=self.state_path,
            runtime_deployment_id=None,
            public_key_pem=self.pub_pem,
            expected_product="noctisapi",
        )

    def test_active_license(self):
        self._write_license(_make_payload(expires_delta=3600))
        d = self._resolve()
        assert d.valid is True
        assert d.decision == "ALLOW"
        assert d.in_grace is False

    def test_license_in_grace_period(self):
        # Expired 1h ago, 7-day grace
        self._write_license(_make_payload(expires_delta=-3600, grace_seconds=604800))
        d = self._resolve()
        assert d.valid is True
        assert d.decision == "GRACE"
        assert d.in_grace is True
        assert d.grace_until is not None
        assert d.tier == "pro"

    def test_license_beyond_grace(self):
        # Expired 8 days ago, 7-day grace
        self._write_license(_make_payload(expires_delta=-(8 * 86400), grace_seconds=7 * 86400))
        d = self._resolve()
        assert d.valid is False
        assert d.decision == "LIMITED"
        assert d.tier == "core"
        assert d.in_grace is False

    def test_missing_license_file(self):
        d = self._resolve()
        assert d.valid is False
        assert d.reason_code == "OFFLINE_LICENSE_MISSING"
