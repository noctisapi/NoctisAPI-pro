"""NOC-017: _CloudflareAccessMiddleware wired into the real admin panel app.

Builds real RS256 tokens against a throwaway key and drives the actual
middleware class from app.panel_mvp through a FastAPI TestClient -- not a
reimplementation of its logic, the real class.
"""
from __future__ import annotations

import base64
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

python_multipart = types.ModuleType("python_multipart")
python_multipart.__version__ = "0.0.20"
sys.modules.setdefault("python_multipart", python_multipart)

_IMPORT_DB_PATH = Path(tempfile.gettempdir()) / "panel_cf_access_import.sqlite"
_conn = sqlite3.connect(str(_IMPORT_DB_PATH), check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT NOT NULL)")
_conn.execute("DELETE FROM alembic_version")
_conn.execute("INSERT INTO alembic_version(version_num) VALUES ('test')")
_conn.commit()
_conn.close()
os.environ.setdefault("HP_DB_PATH", str(_IMPORT_DB_PATH))

import app.cloudflare_access as cloudflare_access
import app.panel_mvp as panel_mvp


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _int_to_b64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return _b64url(value.to_bytes(length, "big"))


_AUD = "test-application-aud-tag"


class _TestKey:
    def __init__(self, kid: str = "test-kid-1"):
        self.kid = kid
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self) -> dict:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kid": self.kid,
            "kty": "RSA",
            "n": _int_to_b64url(numbers.n),
            "e": _int_to_b64url(numbers.e),
        }

    def sign_token(self, claims: dict) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        header_b64 = _b64url(json.dumps(header).encode())
        payload_b64 = _b64url(json.dumps(claims).encode())
        signed_data = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = self.private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
        return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(panel_mvp._CloudflareAccessMiddleware)

    @app.get("/whoami")
    def whoami():
        return {"ok": True}

    return app


class TestCloudflareAccessMiddleware(unittest.TestCase):
    def setUp(self):
        self._old_domain = os.environ.get("CF_ACCESS_TEAM_DOMAIN")
        self._old_aud = os.environ.get("CF_ACCESS_AUD")
        self.key = _TestKey()
        self.now = time.time()
        self.client = TestClient(_build_test_app())

    def tearDown(self):
        for k, old in (
            ("CF_ACCESS_TEAM_DOMAIN", self._old_domain),
            ("CF_ACCESS_AUD", self._old_aud),
        ):
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old
        importlib.reload(cloudflare_access)
        panel_mvp.cloudflare_access = cloudflare_access

    def _enable_access(self):
        os.environ["CF_ACCESS_TEAM_DOMAIN"] = "myteam.cloudflareaccess.com"
        os.environ["CF_ACCESS_AUD"] = _AUD
        importlib.reload(cloudflare_access)
        panel_mvp.cloudflare_access = cloudflare_access
        cloudflare_access.get_jwks = lambda force_refresh=False: {self.key.kid: self.key.jwk()}

    def _valid_token(self) -> str:
        return self.key.sign_token(
            {"aud": [_AUD], "email": "op@example.com", "exp": int(self.now) + 3600, "iat": int(self.now)}
        )

    def test_access_disabled_lets_requests_through_unchanged(self):
        os.environ.pop("CF_ACCESS_TEAM_DOMAIN", None)
        os.environ.pop("CF_ACCESS_AUD", None)
        importlib.reload(cloudflare_access)
        panel_mvp.cloudflare_access = cloudflare_access
        resp = self.client.get("/whoami")
        self.assertEqual(resp.status_code, 200)

    def test_access_enabled_rejects_requests_with_no_token(self):
        self._enable_access()
        resp = self.client.get("/whoami")
        self.assertEqual(resp.status_code, 401)

    def test_access_enabled_accepts_valid_header_token(self):
        self._enable_access()
        resp = self.client.get(
            "/whoami", headers={"Cf-Access-Jwt-Assertion": self._valid_token()}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"ok": True})

    def test_access_enabled_accepts_valid_cookie_token(self):
        self._enable_access()
        resp = self.client.get(
            "/whoami", cookies={"CF_Authorization": self._valid_token()}
        )
        self.assertEqual(resp.status_code, 200)

    def test_access_enabled_rejects_expired_token(self):
        self._enable_access()
        expired = self.key.sign_token(
            {"aud": [_AUD], "exp": int(self.now) - 10, "iat": int(self.now) - 100}
        )
        resp = self.client.get("/whoami", headers={"Cf-Access-Jwt-Assertion": expired})
        self.assertEqual(resp.status_code, 401)

    def test_access_enabled_rejects_wrong_audience(self):
        self._enable_access()
        wrong_aud = self.key.sign_token(
            {"aud": ["someone-elses-app"], "exp": int(self.now) + 3600, "iat": int(self.now)}
        )
        resp = self.client.get("/whoami", headers={"Cf-Access-Jwt-Assertion": wrong_aud})
        self.assertEqual(resp.status_code, 401)

    def test_access_enabled_rejects_token_from_a_revoked_key(self):
        self._enable_access()
        other_key = _TestKey(kid="rotated-out-kid")
        token = other_key.sign_token(
            {"aud": [_AUD], "exp": int(self.now) + 3600, "iat": int(self.now)}
        )
        resp = self.client.get("/whoami", headers={"Cf-Access-Jwt-Assertion": token})
        self.assertEqual(resp.status_code, 401)

    def test_no_bypass_list_even_login_like_paths_require_access(self):
        self._enable_access()
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
