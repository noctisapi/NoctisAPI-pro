"""NOC-017: Cloudflare Access JWT verification.

Crafts real RS256 JWTs with a locally generated throwaway key and feeds
them through app.cloudflare_access.verify_access_jwt with an injected JWKS
(no network call, no real Cloudflare account needed) -- the signature
verification, audience check and expiry/revocation logic are exercised for
real, not mocked away.
"""
from __future__ import annotations

import base64
import importlib
import json
import os
import time
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import app.cloudflare_access as cloudflare_access


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _int_to_b64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return _b64url(value.to_bytes(length, "big"))


class _TestKey:
    def __init__(self, kid: str = "test-kid-1"):
        self.kid = kid
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def jwk(self) -> dict:
        numbers = self.public_key.public_numbers()
        return {
            "kid": self.kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": _int_to_b64url(numbers.n),
            "e": _int_to_b64url(numbers.e),
        }

    def sign_token(self, claims: dict, kid: str | None = None, alg: str = "RS256") -> str:
        header = {"alg": alg, "typ": "JWT", "kid": kid if kid is not None else self.kid}
        header_b64 = _b64url(json.dumps(header).encode())
        payload_b64 = _b64url(json.dumps(claims).encode())
        signed_data = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = self.private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
        return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


_AUD = "test-application-aud-tag"


def _base_claims(now: float) -> dict:
    return {
        "aud": [_AUD],
        "email": "operator@example.com",
        "exp": int(now) + 3600,
        "iat": int(now),
        "nbf": int(now) - 5,
    }


class TestVerifyAccessJwt(unittest.TestCase):
    def setUp(self):
        self.key = _TestKey()
        self.jwks = {self.key.kid: self.key.jwk()}
        self.now = time.time()

    def test_valid_token_is_accepted(self):
        token = self.key.sign_token(_base_claims(self.now))
        claims = cloudflare_access.verify_access_jwt(
            token, jwks=self.jwks, now=self.now, expected_aud=_AUD
        )
        self.assertEqual(claims["email"], "operator@example.com")

    def test_expired_token_is_rejected(self):
        claims = _base_claims(self.now)
        claims["exp"] = int(self.now) - 10  # already expired
        token = self.key.sign_token(claims)
        with self.assertRaises(cloudflare_access.AccessTokenError):
            cloudflare_access.verify_access_jwt(
                token, jwks=self.jwks, now=self.now, expected_aud=_AUD
            )

    def test_not_yet_valid_token_is_rejected(self):
        claims = _base_claims(self.now)
        claims["nbf"] = int(self.now) + 3600  # not valid for another hour
        token = self.key.sign_token(claims)
        with self.assertRaises(cloudflare_access.AccessTokenError):
            cloudflare_access.verify_access_jwt(
                token, jwks=self.jwks, now=self.now, expected_aud=_AUD
            )

    def test_wrong_audience_is_rejected(self):
        claims = _base_claims(self.now)
        claims["aud"] = ["some-other-applications-aud-tag"]
        token = self.key.sign_token(claims)
        with self.assertRaises(cloudflare_access.AccessTokenError):
            cloudflare_access.verify_access_jwt(
                token, jwks=self.jwks, now=self.now, expected_aud=_AUD
            )

    def test_tampered_payload_fails_signature_check(self):
        token = self.key.sign_token(_base_claims(self.now))
        header_b64, payload_b64, sig_b64 = token.split(".")
        forged_claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        forged_claims["email"] = "attacker@example.com"
        forged_payload_b64 = _b64url(json.dumps(forged_claims).encode())
        forged_token = f"{header_b64}.{forged_payload_b64}.{sig_b64}"
        with self.assertRaises(cloudflare_access.AccessTokenError):
            cloudflare_access.verify_access_jwt(
                forged_token, jwks=self.jwks, now=self.now, expected_aud=_AUD
            )

    def test_revoked_key_is_rejected(self):
        """Simulates Cloudflare rotating out a signing key: a token signed
        with a key no longer present in the JWKS must be rejected, even
        though it would have verified fine before the rotation."""
        token = self.key.sign_token(_base_claims(self.now))
        rotated_jwks: dict = {}  # the signing key id is no longer published
        with self.assertRaises(cloudflare_access.AccessTokenError):
            cloudflare_access.verify_access_jwt(
                token, jwks=rotated_jwks, now=self.now, expected_aud=_AUD
            )

    def test_unsupported_algorithm_is_rejected(self):
        claims = _base_claims(self.now)
        token = self.key.sign_token(claims, alg="none")
        with self.assertRaises(cloudflare_access.AccessTokenError):
            cloudflare_access.verify_access_jwt(
                token, jwks=self.jwks, now=self.now, expected_aud=_AUD
            )

    def test_malformed_token_is_rejected(self):
        with self.assertRaises(cloudflare_access.AccessTokenError):
            cloudflare_access.verify_access_jwt(
                "not-a-jwt", jwks=self.jwks, now=self.now, expected_aud=_AUD
            )


class TestIsEnabled(unittest.TestCase):
    def setUp(self):
        self._old_domain = os.environ.get("CF_ACCESS_TEAM_DOMAIN")
        self._old_aud = os.environ.get("CF_ACCESS_AUD")

    def tearDown(self):
        for key, old in (
            ("CF_ACCESS_TEAM_DOMAIN", self._old_domain),
            ("CF_ACCESS_AUD", self._old_aud),
        ):
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
        importlib.reload(cloudflare_access)

    def test_disabled_when_unset(self):
        os.environ.pop("CF_ACCESS_TEAM_DOMAIN", None)
        os.environ.pop("CF_ACCESS_AUD", None)
        module = importlib.reload(cloudflare_access)
        self.assertFalse(module.is_enabled())

    def test_disabled_when_only_one_var_set(self):
        os.environ["CF_ACCESS_TEAM_DOMAIN"] = "myteam.cloudflareaccess.com"
        os.environ.pop("CF_ACCESS_AUD", None)
        module = importlib.reload(cloudflare_access)
        self.assertFalse(module.is_enabled())

    def test_enabled_when_both_set(self):
        os.environ["CF_ACCESS_TEAM_DOMAIN"] = "myteam.cloudflareaccess.com"
        os.environ["CF_ACCESS_AUD"] = _AUD
        module = importlib.reload(cloudflare_access)
        self.assertTrue(module.is_enabled())


if __name__ == "__main__":
    unittest.main()
