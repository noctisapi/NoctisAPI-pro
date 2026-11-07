"""NOC-041: signed Managed Mode, generation rollback and feature gates."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import pro_ops
from honey_licensing.managed_mode import resolve_managed_entitlements, signed_envelope_payload_bytes


def _keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def _write_envelope(path, private, *, deployment_id="dep-1", generation=1, features=None):
    payload = {
        "product": "noctisapi",
        "deployment_id": deployment_id,
        "generation": generation,
        "entitlements": {
            "schema_version": 1,
            "plan_id": "managed-pro",
            "mode": "managed",
            "features": features if features is not None else ["cases"],
            "quotas": {"max_cases": 10},
            "starts_at": "2026-01-01T00:00:00Z",
            "expires_at": "2027-01-01T00:00:00Z",
        },
    }
    signature = private.sign(
        signed_envelope_payload_bytes(payload),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    path.write_text(json.dumps({
        "schema_version": 1,
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }), encoding="utf-8")


def test_signed_managed_document_is_bound_and_persisted(tmp_path):
    private, public = _keys()
    path = tmp_path / "entitlements.json"
    state = tmp_path / "entitlements-state.json"
    _write_envelope(path, private)
    result = resolve_managed_entitlements(
        document_path=str(path), state_path=str(state), public_key_pem=public,
        deployment_id="dep-1", now=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    assert result.valid is True
    assert result.document is not None
    assert json.loads(state.read_text()) == {"deployment_id": "dep-1", "max_generation": 1}


def test_tamper_mismatch_and_rollback_are_denied(tmp_path):
    private, public = _keys()
    path = tmp_path / "entitlements.json"
    state = tmp_path / "entitlements-state.json"
    _write_envelope(path, private, generation=2)
    assert resolve_managed_entitlements(
        document_path=str(path), state_path=str(state), public_key_pem=public,
        deployment_id="wrong", now=datetime(2026, 2, 1, tzinfo=timezone.utc),
    ).reason_code == "MANAGED_DEPLOYMENT_MISMATCH"
    assert resolve_managed_entitlements(
        document_path=str(path), state_path=str(state), public_key_pem=public,
        deployment_id="dep-1", now=datetime(2026, 2, 1, tzinfo=timezone.utc),
    ).valid is True
    _write_envelope(path, private, generation=1)
    assert resolve_managed_entitlements(
        document_path=str(path), state_path=str(state), public_key_pem=public,
        deployment_id="dep-1", now=datetime(2026, 2, 1, tzinfo=timezone.utc),
    ).reason_code == "MANAGED_ROLLBACK_DETECTED"

    tampered = json.loads(path.read_text())
    tampered["payload"]["deployment_id"] = "dep-1"
    tampered["payload"]["entitlements"]["features"] = ["analytics"]
    path.write_text(json.dumps(tampered), encoding="utf-8")
    assert resolve_managed_entitlements(
        document_path=str(path), state_path=str(tmp_path / "tamper-state.json"), public_key_pem=public,
        deployment_id="dep-1", now=datetime(2026, 2, 1, tzinfo=timezone.utc),
    ).reason_code == "MANAGED_LICENSE_SIGNATURE_INVALID"


def test_managed_feature_gate_does_not_become_a_global_bypass(monkeypatch):
    monkeypatch.setattr(pro_ops.pro_license, "get_backend_license_snapshot", lambda **_: {
        "pro_enabled": True,
        "valid": True,
        "entitlements": {"mode": "managed", "tier": "pro", "features": ["cases"]},
    })
    assert pro_ops.authorize_pro_feature(feature="cases")[0] is True
    assert pro_ops.authorize_pro_feature(feature="analytics")[0] is False

    monkeypatch.setattr(pro_ops.pro_license, "get_backend_license_snapshot", lambda **_: {
        "pro_enabled": True,
        "valid": True,
        "entitlements": {"mode": "managed", "tier": "pro", "features": []},
    })
    assert pro_ops.authorize_pro_feature(feature="cases")[0] is False
