from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PUBLIC_KEY_PATH = "/app/app/licensing_server_public_key.pem"
_EXPECTED_PUBKEY_SHA256 = "118a86fc8f1c69609a71e3f314957a8221dd03febdf01745dc0be0d0a4088aea"


def load_public_key_pem() -> bytes:
    """Load and verify the RSA public key PEM from the fixed image path.

    Raises RuntimeError if the file is missing, unreadable, empty, or tampered.
    Callers should catch this and degrade to CORE.
    """
    try:
        with open(PUBLIC_KEY_PATH, "rb") as f:
            data = f.read()
        if not data:
            raise ValueError("PEM file is empty")
        if hashlib.sha256(data).hexdigest() != _EXPECTED_PUBKEY_SHA256:
            raise ValueError("public key integrity check failed")
        return data
    except Exception as exc:
        raise RuntimeError(
            f"License public key unavailable at {PUBLIC_KEY_PATH}: {exc}"
        ) from exc

logger = logging.getLogger(__name__)

# ── helpers ──────────────────────────────────────────────────────────────────

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


# ── domain types ─────────────────────────────────────────────────────────────

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
    license_generation: int   # maps from payload.license_version
    deployment_id: Optional[str]  # maps from payload.machine_fingerprint
    in_grace: bool = False          # True when expired but within grace_seconds window
    grace_until: Optional[int] = None  # epoch when grace ends
    online_check_required: bool = True  # from signed payload; False = offline-only license


# ── verification pipeline ─────────────────────────────────────────────────────

class LicenseLoader:
    def __init__(self, *, license_path: str) -> None:
        self.license_path = str(license_path or "").strip()

    def load(self) -> Optional[dict[str, Any]]:
        if not self.license_path:
            return None
        obj = _safe_load_json(self.license_path)
        return obj if obj else None


class LicenseVerifier:
    """Verify a schema_version=1 license document.

    The document must have:
      { "schema_version": 1, "payload": {...}, "signature": "<base64url>" }

    The signature is RSA PKCS1v15+SHA256 over canonical_json_bytes(payload).
    """

    def __init__(self, *, public_key_pem: bytes) -> None:
        if not public_key_pem:
            raise ValueError("public_key_pem must not be empty")
        self._public_key = load_pem_public_key(public_key_pem)

    def verify(self, document: dict[str, Any]) -> tuple[bool, Optional[dict[str, Any]], str]:
        if not isinstance(document, dict):
            return False, None, "license_json_invalid"

        schema_version = document.get("schema_version")
        if schema_version != 1:
            return False, None, "license_schema_version_unsupported"

        payload = document.get("payload")
        if not isinstance(payload, dict):
            return False, None, "license_json_invalid"

        signature = document.get("signature")
        if not isinstance(signature, str) or not signature.strip():
            return False, None, "license_signature_missing"

        try:
            sig_bytes = _b64url_decode(signature.strip())
            canonical = _canonical_json_bytes(payload)
            self._public_key.verify(sig_bytes, canonical, padding.PKCS1v15(), hashes.SHA256())
        except Exception as exc:
            logger.debug("license signature invalid: %s", exc)
            return False, None, "license_signature_invalid"

        return True, payload, "ok"


class LicenseValidator:
    """Validate the semantic claims of a verified payload.

    Checks (in order):
      1. product matches expected_product (case-insensitive)
      2. tier is a known value
      3. not expired (ISO datetime in expires_at)
      4. machine_fingerprint matches instance_fingerprint when non-null
    """

    def __init__(
        self,
        *,
        expected_product: str = "noctisapi",
        instance_fingerprint: Optional[str] = None,
    ) -> None:
        self.expected_product = str(expected_product or "").strip().lower()
        self.instance_fingerprint = (str(instance_fingerprint or "").strip() or None)

    def validate(
        self, payload: dict[str, Any], *, now_epoch: Optional[int] = None
    ) -> tuple[bool, str, dict[str, Any]]:
        now = int(now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp())

        # 1 — product
        product = str(payload.get("product") or "").strip().lower()
        if self.expected_product and product != self.expected_product:
            logger.info("license product mismatch: got %r expected %r", product, self.expected_product)
            return False, "license_product_mismatch", {}

        # 2 — tier
        tier = str(payload.get("tier") or "").strip().lower()
        if tier not in ("pro", "core"):
            return False, "license_tier_invalid", {}

        # 3 — expiry
        expires_at = _parse_iso_epoch(payload.get("expires_at"))
        if expires_at is not None and now > expires_at:
            grace_seconds = int(payload.get("grace_seconds") or 0)
            if grace_seconds > 0:
                grace_until = expires_at + grace_seconds
                if now <= grace_until:
                    logger.info(
                        "license expired at epoch %d but in grace until %d (now %d)",
                        expires_at, grace_until, now,
                    )
                    return True, "grace", {
                        "expires_at": int(expires_at),
                        "grace_until": int(grace_until),
                    }
            logger.info("license expired at epoch %d (now %d)", expires_at, now)
            return False, "license_expired", {"expires_at": int(expires_at)}

        # 4 — machine fingerprint
        machine_fp = payload.get("machine_fingerprint")
        if machine_fp is not None:
            fp_str = str(machine_fp).strip()
            if not fp_str:
                pass  # treat empty string fingerprint as unbound
            elif not self.instance_fingerprint:
                logger.warning("license requires machine_fingerprint but none configured")
                return False, "license_fingerprint_required", {}
            elif fp_str != self.instance_fingerprint:
                logger.warning("license machine_fingerprint mismatch")
                return False, "license_fingerprint_mismatch", {}

        return True, "ok", {"expires_at": expires_at}


class LicenseStateResolver:
    """Track license_version to detect rollback attacks, persist deployment binding."""

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

    def resolve(
        self,
        *,
        payload: dict[str, Any],
        validation_ok: bool,
        validation_reason: str,
        details: dict[str, Any],
    ) -> LocalLicenseDecision:
        tier = str(payload.get("tier") or "core").strip().lower() or "core"
        if tier not in ("core", "pro"):
            tier = "core"
        online_check_required = bool(payload.get("online_check_required", True))
        features = tuple(
            str(x or "").strip().lower()
            for x in (payload.get("features") or [])
            if str(x or "").strip()
        )
        entitlements = {"tier": tier, "features": list(features)}
        license_id = (str(payload.get("license_id") or "").strip() or None)
        # license_version replaces old license_generation
        generation = int(payload.get("license_version") or 0)
        machine_fp = payload.get("machine_fingerprint")
        bound_deployment = (str(machine_fp).strip() if machine_fp else None) or None

        state = self._load_state()
        licenses = state.setdefault("licenses", {})
        row = licenses.setdefault(license_id or "_unknown", {}) if license_id else {}

        if validation_ok and license_id:
            max_generation = int(row.get("max_generation") or 0)
            if generation < max_generation:
                logger.warning(
                    "license rollback detected: version %d < max seen %d", generation, max_generation
                )
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

        in_grace = (validation_reason == "grace")
        grace_until: Optional[int] = details.get("grace_until") if in_grace else None

        return LocalLicenseDecision(
            valid=(tier == "pro"),
            decision="GRACE" if (in_grace and tier == "pro") else ("ALLOW" if tier == "pro" else "LIMITED"),
            reason_code="GRACE" if in_grace else "OK",
            tier=tier,
            features=features if tier == "pro" else tuple(),
            entitlements=entitlements,
            expires_at=details.get("expires_at"),
            source="offline_license",
            license_id=license_id,
            license_generation=generation,
            deployment_id=bound_deployment,
            in_grace=in_grace,
            grace_until=grace_until,
            online_check_required=online_check_required,
        )


# ── main entry point ──────────────────────────────────────────────────────────

def resolve_local_license_state(
    *,
    license_path: str,
    state_path: str,
    runtime_deployment_id: Optional[str],
    public_key_pem: bytes,
    expected_product: str = "noctisapi",
    instance_fingerprint: Optional[str] = None,
) -> LocalLicenseDecision:
    """Full offline license validation pipeline.

    Steps:
      1. Load license.json from disk
      2. Verify RSA signature (schema_version=1)
      3. Validate claims (product, tier, expiry, fingerprint)
      4. Resolve state (rollback detection, deployment binding)
    """
    def _limited(reason_code: str) -> LocalLicenseDecision:
        return LocalLicenseDecision(
            valid=False,
            decision="LIMITED",
            reason_code=reason_code,
            tier="core",
            features=tuple(),
            entitlements={"tier": "core", "features": []},
            expires_at=None,
            source="offline_license",
            license_id=None,
            license_generation=0,
            deployment_id=None,
        )

    loader = LicenseLoader(license_path=license_path)
    document = loader.load()
    if not document:
        logger.info("offline license file not found or empty: %s", license_path)
        return _limited("OFFLINE_LICENSE_MISSING")

    try:
        verifier = LicenseVerifier(public_key_pem=public_key_pem)
    except Exception as exc:
        logger.error("failed to load RSA public key: %s", exc)
        return _limited("LICENSE_PUBLIC_KEY_INVALID")

    ok_sig, payload, sig_reason = verifier.verify(document)
    if not ok_sig or payload is None:
        logger.info("license verification failed: %s", sig_reason)
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

    validator = LicenseValidator(
        expected_product=expected_product,
        instance_fingerprint=instance_fingerprint,
    )
    ok_claims, reason, details = validator.validate(payload)
    resolver = LicenseStateResolver(
        state_path=state_path,
        runtime_deployment_id=runtime_deployment_id,
    )
    return resolver.resolve(
        payload=payload,
        validation_ok=ok_claims,
        validation_reason=reason,
        details=details,
    )
