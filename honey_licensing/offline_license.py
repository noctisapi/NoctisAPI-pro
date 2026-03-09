from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64url_decode(value: str) -> bytes:
    raw = str(value or "").strip()
    if not raw:
        return b""
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    return base64.urlsafe_b64decode((raw + pad).encode("ascii"))


def _parse_iso_epoch(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return None


def _safe_load_json(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _safe_write_json(path: str, payload: dict[str, Any]) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="offline-license-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


@dataclass(frozen=True)
class LocalLicenseDecision:
    valid: bool
    decision: str
    reason_code: str
    tier: str
    features: tuple[str, ...]
    entitlements: dict[str, Any]
    expires_at: Optional[int]
    source: str
    license_id: Optional[str]
    license_generation: int
    deployment_id: Optional[str]


class LicenseLoader:
    def __init__(self, *, license_path: str) -> None:
        self.license_path = str(license_path or "").strip()

    def load(self) -> Optional[dict[str, Any]]:
        if not self.license_path:
            return None
        obj = _safe_load_json(self.license_path)
        return obj if obj else None


class LicenseVerifier:
    def __init__(self, *, trusted_keys: Dict[str, str]) -> None:
        self._trusted_keys = {str(k): str(v) for k, v in (trusted_keys or {}).items() if str(k).strip() and str(v).strip()}

    def verify(self, document: dict[str, Any]) -> tuple[bool, Optional[dict[str, Any]], str]:
        if not isinstance(document, dict):
            return False, None, "license_json_invalid"
        payload = document.get("payload")
        signature = document.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            return False, None, "license_json_invalid"
        if str(signature.get("alg") or "").strip() != "Ed25519":
            return False, None, "license_signature_alg_invalid"
        kid = str(signature.get("kid") or "").strip()
        sig_b64 = str(signature.get("value") or "").strip()
        pub_b64 = self._trusted_keys.get(kid)
        if not pub_b64:
            return False, None, "license_kid_not_trusted"
        try:
            pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(pub_b64))
            pub.verify(_b64url_decode(sig_b64), _canonical_json_bytes(payload))
        except Exception:
            return False, None, "license_signature_invalid"
        return True, payload, "ok"


class LicenseValidator:
    def validate(self, payload: dict[str, Any], *, now_epoch: Optional[int] = None) -> tuple[bool, str, dict[str, Any]]:
        now = int(now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp())
        status = str(payload.get("status") or "active").strip().lower()
        if status != "active":
            return False, f"license_{status}", {}

        expires_at = _parse_iso_epoch(payload.get("expires_at"))
        policy = payload.get("offline_policy") if isinstance(payload.get("offline_policy"), dict) else {}
        grace_raw = policy.get("offline_grace_seconds") if isinstance(policy, dict) else None
        try:
            grace = max(0, int(grace_raw)) if grace_raw is not None else 0
        except Exception:
            return False, "license_grace_invalid", {}

        if expires_at is not None and now > expires_at:
            if now <= (expires_at + grace):
                return True, "pro_grace", {"expires_at": int(expires_at), "in_grace": True}
            return False, "license_expired", {"expires_at": int(expires_at)}

        return True, "pro_active", {"expires_at": expires_at, "in_grace": False}


class LicenseStateResolver:
    def __init__(self, *, state_path: str, runtime_deployment_id: Optional[str]) -> None:
        self.state_path = str(state_path or "").strip()
        self.runtime_deployment_id = (str(runtime_deployment_id or "").strip() or None)

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path:
            return {"licenses": {}}
        obj = _safe_load_json(self.state_path)
        if not isinstance(obj, dict):
            return {"licenses": {}}
        if not isinstance(obj.get("licenses"), dict):
            obj["licenses"] = {}
        return obj

    def _save_state(self, state: dict[str, Any]) -> None:
        if not self.state_path:
            return
        _safe_write_json(self.state_path, state)

    def resolve(self, *, payload: dict[str, Any], validation_ok: bool, validation_reason: str, details: dict[str, Any]) -> LocalLicenseDecision:
        tier = str(payload.get("tier") or "core").strip().lower() or "core"
        if tier not in ("core", "pro"):
            tier = "core"
        features = tuple(str(x or "").strip().lower() for x in (payload.get("features") or []) if str(x or "").strip())
        entitlements = {"tier": tier, "features": list(features)}
        license_id = (str(payload.get("license_id") or "").strip() or None)
        generation = int(payload.get("license_generation") or 0)
        deployment_binding = payload.get("deployment_binding") if isinstance(payload.get("deployment_binding"), dict) else {}
        binding_mode = str((deployment_binding or {}).get("mode") or "soft").strip().lower() or "soft"
        bound_deployment = (str((deployment_binding or {}).get("deployment_id") or "").strip() or None)

        state = self._load_state()
        licenses = state.setdefault("licenses", {})
        row = licenses.setdefault(license_id or "_unknown", {}) if license_id else {}

        if validation_ok and license_id:
            max_generation = int(row.get("max_generation") or 0)
            if generation < max_generation:
                return LocalLicenseDecision(
                    valid=False,
                    decision="LIMITED",
                    reason_code="ROLLBACK_DETECTED",
                    tier="core",
                    features=tuple(),
                    entitlements={"tier": "core", "features": []},
                    expires_at=details.get("expires_at"),
                    source="offline_license",
                    license_id=license_id,
                    license_generation=generation,
                    deployment_id=bound_deployment,
                )
            if generation > max_generation:
                row["max_generation"] = generation

            persisted_dep = (str(row.get("deployment_id") or "").strip() or None)
            if self.runtime_deployment_id and not persisted_dep:
                row["deployment_id"] = self.runtime_deployment_id
                persisted_dep = self.runtime_deployment_id
            if binding_mode == "soft":
                if bound_deployment and self.runtime_deployment_id and bound_deployment != self.runtime_deployment_id:
                    return LocalLicenseDecision(
                        valid=False,
                        decision="LIMITED",
                        reason_code="DEPLOYMENT_MISMATCH",
                        tier="core",
                        features=tuple(),
                        entitlements={"tier": "core", "features": []},
                        expires_at=details.get("expires_at"),
                        source="offline_license",
                        license_id=license_id,
                        license_generation=generation,
                        deployment_id=bound_deployment,
                    )
                if bound_deployment and persisted_dep and bound_deployment != persisted_dep:
                    return LocalLicenseDecision(
                        valid=False,
                        decision="LIMITED",
                        reason_code="DEPLOYMENT_MISMATCH",
                        tier="core",
                        features=tuple(),
                        entitlements={"tier": "core", "features": []},
                        expires_at=details.get("expires_at"),
                        source="offline_license",
                        license_id=license_id,
                        license_generation=generation,
                        deployment_id=bound_deployment,
                    )
            self._save_state(state)

        if not validation_ok:
            return LocalLicenseDecision(
                valid=False,
                decision="LIMITED",
                reason_code=validation_reason.upper(),
                tier="core",
                features=tuple(),
                entitlements={"tier": "core", "features": []},
                expires_at=details.get("expires_at"),
                source="offline_license",
                license_id=license_id,
                license_generation=generation,
                deployment_id=bound_deployment,
            )

        reason_code = "PRO_GRACE" if validation_reason == "pro_grace" else "OK"
        return LocalLicenseDecision(
            valid=(tier == "pro"),
            decision="ALLOW" if tier == "pro" else "LIMITED",
            reason_code=reason_code,
            tier=tier,
            features=features if tier == "pro" else tuple(),
            entitlements=entitlements,
            expires_at=details.get("expires_at"),
            source="offline_license",
            license_id=license_id,
            license_generation=generation,
            deployment_id=bound_deployment,
        )


def load_trusted_public_keys_from_env() -> Dict[str, str]:
    keys: Dict[str, str] = {}
    raw_json = (os.getenv("HP_OFFLINE_PUBLIC_KEYS_JSON") or os.getenv("LICENSING_OFFLINE_PUBLIC_KEYS_JSON") or "").strip()
    if raw_json:
        try:
            obj = json.loads(raw_json)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    kk = str(k or "").strip()
                    vv = str(v or "").strip()
                    if kk and vv:
                        keys[kk] = vv
        except Exception:
            pass

    keys_path = (os.getenv("HP_OFFLINE_PUBLIC_KEYS_PATH") or os.getenv("LICENSING_OFFLINE_PUBLIC_KEYS_PATH") or "").strip()
    if keys_path:
        obj = _safe_load_json(keys_path)
        if isinstance(obj, dict):
            for k, v in obj.items():
                kk = str(k or "").strip()
                vv = str(v or "").strip()
                if kk and vv:
                    keys[kk] = vv

    single_kid = (os.getenv("HP_OFFLINE_PUBLIC_KEY_KID") or "").strip()
    single_raw = (os.getenv("HP_OFFLINE_PUBLIC_KEY_RAW_B64") or "").strip()
    if single_kid and single_raw:
        keys[single_kid] = single_raw
    return keys


def resolve_local_license_state(
    *,
    license_path: str,
    state_path: str,
    runtime_deployment_id: Optional[str],
    trusted_public_keys: Dict[str, str],
) -> LocalLicenseDecision:
    loader = LicenseLoader(license_path=license_path)
    document = loader.load()
    if not document:
        return LocalLicenseDecision(
            valid=False,
            decision="LIMITED",
            reason_code="OFFLINE_LICENSE_MISSING",
            tier="core",
            features=tuple(),
            entitlements={"tier": "core", "features": []},
            expires_at=None,
            source="offline_license",
            license_id=None,
            license_generation=0,
            deployment_id=None,
        )

    verifier = LicenseVerifier(trusted_keys=trusted_public_keys)
    ok_sig, payload, sig_reason = verifier.verify(document)
    if not ok_sig or payload is None:
        return LocalLicenseDecision(
            valid=False,
            decision="LIMITED",
            reason_code=sig_reason.upper(),
            tier="core",
            features=tuple(),
            entitlements={"tier": "core", "features": []},
            expires_at=None,
            source="offline_license",
            license_id=None,
            license_generation=0,
            deployment_id=None,
        )

    validator = LicenseValidator()
    ok_claims, reason, details = validator.validate(payload)
    resolver = LicenseStateResolver(state_path=state_path, runtime_deployment_id=runtime_deployment_id)
    return resolver.resolve(payload=payload, validation_ok=ok_claims, validation_reason=reason, details=details)

