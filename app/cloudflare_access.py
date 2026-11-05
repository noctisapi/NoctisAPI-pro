"""Cloudflare Access JWT verification for the admin console (NOC-017).

Defense-in-depth on top of the per-user session gate
(app.panel_mvp._PanelAuthMiddleware, NOC-018), not a replacement for it --
backend RBAC is NOC-019's job. This module's only
claim is: when Cloudflare Access is configured for this installation, every
request reaching the panel carries a cryptographically valid Access JWT,
verified against Cloudflare's own JWKS for that team -- never a bare
Cf-Access-* header taken on faith, since headers are otherwise just
attacker-controllable text like any other, and the tunnel alone (NOC-016)
only guarantees traffic came from Cloudflare's edge, not that Access
actually authenticated it.

Inert when CF_ACCESS_TEAM_DOMAIN or CF_ACCESS_AUD is unset: self-hosted
installations that haven't configured Access yet keep today's behavior
unchanged.
"""
from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict, Optional

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CF_ACCESS_TEAM_DOMAIN = os.getenv("CF_ACCESS_TEAM_DOMAIN", "").strip()
CF_ACCESS_AUD = os.getenv("CF_ACCESS_AUD", "").strip()

# Cloudflare rotates Access signing keys infrequently; a short-lived cache
# avoids a JWKS fetch on every single request without risking long-lived
# staleness if a key is ever rotated/revoked.
_JWKS_CACHE_TTL_SECONDS = 3600

_jwks_cache: Dict[str, Any] = {"ts": 0.0, "keys": {}}


class AccessTokenError(Exception):
    """Raised for any reason a Cf-Access-Jwt-Assertion token is rejected."""


def is_enabled() -> bool:
    return bool(CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD)


def _certs_url() -> str:
    return f"https://{CF_ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs"


def _fetch_jwks() -> Dict[str, Any]:
    resp = httpx.get(_certs_url(), timeout=5.0)
    resp.raise_for_status()
    data = resp.json()
    return {key["kid"]: key for key in data.get("keys", []) if "kid" in key}


def get_jwks(force_refresh: bool = False) -> Dict[str, Any]:
    now = time.time()
    if not force_refresh and _jwks_cache["keys"] and now - _jwks_cache["ts"] < _JWKS_CACHE_TTL_SECONDS:
        return _jwks_cache["keys"]
    keys = _fetch_jwks()
    _jwks_cache["keys"] = keys
    _jwks_cache["ts"] = now
    return keys


def invalidate_jwks_cache() -> None:
    _jwks_cache["ts"] = 0.0
    _jwks_cache["keys"] = {}


def _b64url_decode(segment: str) -> bytes:
    pad = -len(segment) % 4
    return base64.urlsafe_b64decode(segment + "=" * pad)


def _jwk_to_rsa_public_key(jwk: Dict[str, Any]) -> rsa.RSAPublicKey:
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def verify_access_jwt(
    token: str,
    *,
    jwks: Optional[Dict[str, Any]] = None,
    now: Optional[float] = None,
    expected_aud: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a Cf-Access-Jwt-Assertion token end to end.

    Raises AccessTokenError for any failure (malformed, unknown key id, bad
    signature, wrong audience, expired, not yet valid). Returns the decoded
    claims only on full success.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise AccessTokenError("malformed token")

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except Exception as exc:
        raise AccessTokenError(f"malformed token: {exc}")

    if header.get("alg") != "RS256":
        raise AccessTokenError(f"unsupported alg: {header.get('alg')!r}")

    kid = header.get("kid")
    keyset = jwks if jwks is not None else get_jwks()
    jwk = keyset.get(kid)
    if not jwk:
        # Key rotated since last cache fill -- refresh once before giving up.
        if jwks is None:
            keyset = get_jwks(force_refresh=True)
            jwk = keyset.get(kid)
        if not jwk:
            raise AccessTokenError("unknown key id")

    public_key = _jwk_to_rsa_public_key(jwk)
    signed_data = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        public_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise AccessTokenError("invalid signature")

    aud_claim = payload.get("aud")
    auds = aud_claim if isinstance(aud_claim, list) else [aud_claim]
    aud_to_check = expected_aud if expected_aud is not None else CF_ACCESS_AUD
    if aud_to_check not in auds:
        raise AccessTokenError("audience mismatch")

    current_time = now if now is not None else time.time()
    exp = payload.get("exp")
    if exp is None or current_time >= exp:
        raise AccessTokenError("expired")
    not_before = payload.get("nbf", payload.get("iat"))
    if not_before is not None and current_time < not_before:
        raise AccessTokenError("not yet valid")

    return payload
