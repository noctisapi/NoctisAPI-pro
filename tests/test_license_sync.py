"""
Tests for the license sync client (LicenseSyncRequest/Response, OnlineLicenseClient.sync).

Uses httpx mock transport — no real network calls.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import httpx

from honey_licensing.online_client import (
    LicenseSyncRequest,
    LicenseSyncResponse,
    OnlineCheckError,
    OnlineLicenseClient,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _client() -> OnlineLicenseClient:
    return OnlineLicenseClient(
        base_url="https://licenses.example.com",
        shared_secret="test-secret",
        timeout_seconds=5.0,
        max_retries=0,
    )


def _sync_req(local_gen: int = 0) -> LicenseSyncRequest:
    return LicenseSyncRequest(
        license_id="lic-abc",
        instance_id="inst-xyz",
        product="noctisapi",
        version="1.0.0",
        local_generation=local_gen,
        client_tier="pro",
    )


def _mock_response(status_code: int, body: dict) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json=body,
        request=httpx.Request("POST", "https://licenses.example.com/v1/licenses/sync"),
    )


# ── sync response parsing ─────────────────────────────────────────────────────

class TestSyncClientParsing:
    def test_unchanged_response(self):
        resp_body = {"status": "unchanged", "license_generation": 3}
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = _mock_response(200, resp_body)

            result = _client().sync(_sync_req(local_gen=3))

        assert result.status == "unchanged"
        assert result.license_generation == 3
        assert result.license_doc is None

    def test_active_with_doc(self):
        doc = {"schema_version": 1, "payload": {"tier": "pro"}, "signature": "abc"}
        resp_body = {"status": "active", "license_generation": 5, "license_doc": doc}
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = _mock_response(200, resp_body)

            result = _client().sync(_sync_req(local_gen=2))

        assert result.status == "active"
        assert result.license_generation == 5
        assert result.license_doc == doc

    def test_revoked_response(self):
        resp_body = {"status": "revoked", "reason": "license_revoked"}
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = _mock_response(200, resp_body)

            result = _client().sync(_sync_req())

        assert result.status == "revoked"
        assert result.license_doc is None
        assert result.reason == "license_revoked"

    def test_expired_response(self):
        resp_body = {"status": "expired"}
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = _mock_response(200, resp_body)

            result = _client().sync(_sync_req())

        assert result.status == "expired"

    def test_401_raises_online_check_error(self):
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = httpx.Response(
                status_code=401,
                json={"detail": "invalid_check_token"},
                request=httpx.Request("POST", "https://licenses.example.com/v1/licenses/sync"),
            )

            with pytest.raises(OnlineCheckError, match="401"):
                _client().sync(_sync_req())

    def test_404_raises_online_check_error(self):
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = httpx.Response(
                status_code=404,
                json={"detail": "license_not_found"},
                request=httpx.Request("POST", "https://licenses.example.com/v1/licenses/sync"),
            )

            with pytest.raises(OnlineCheckError, match="404"):
                _client().sync(_sync_req())

    def test_invalid_status_raises(self):
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = _mock_response(200, {"status": "bogus_value"})

            with pytest.raises(OnlineCheckError, match="unexpected status"):
                _client().sync(_sync_req())

    def test_sends_local_generation_in_payload(self):
        resp_body = {"status": "unchanged", "license_generation": 7}
        captured: dict = {}
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)

            def capture_post(url, json=None, headers=None, **kw):
                captured["json"] = json
                return _mock_response(200, resp_body)

            mock_client.post.side_effect = capture_post
            _client().sync(_sync_req(local_gen=4))

        assert captured["json"]["local_generation"] == 4
        assert captured["json"]["license_id"] == "lic-abc"
        assert captured["json"]["client_tier"] == "pro"

    def test_network_error_raises_online_check_error(self):
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.ConnectError("connection refused")

            with pytest.raises(OnlineCheckError, match="network"):
                _client().sync(_sync_req())


# ── LicenseCheckResponse includes license_generation ─────────────────────────

class TestCheckResponseLicenseGeneration:
    def test_check_response_parses_generation(self):
        from honey_licensing.online_client import LicenseCheckRequest

        resp_body = {
            "status": "active",
            "expires_at": "2027-01-01T00:00:00Z",
            "grace_period_seconds": 259200,
            "license_generation": 3,
        }
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = httpx.Response(
                status_code=200,
                json=resp_body,
                request=httpx.Request("POST", "https://licenses.example.com/v1/licenses/check"),
            )

            client = OnlineLicenseClient(
                base_url="https://licenses.example.com",
                shared_secret="s",
                max_retries=0,
            )
            result = client.check(LicenseCheckRequest(
                license_id="lic-1",
                instance_id="inst-1",
                product="noctisapi",
                version="1.0",
            ))

        assert result.license_generation == 3

    def test_check_response_missing_generation_is_none(self):
        from honey_licensing.online_client import LicenseCheckRequest

        resp_body = {"status": "active"}
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = httpx.Response(
                status_code=200,
                json=resp_body,
                request=httpx.Request("POST", "https://licenses.example.com/v1/licenses/check"),
            )

            client = OnlineLicenseClient(
                base_url="https://licenses.example.com",
                shared_secret="s",
                max_retries=0,
            )
            result = client.check(LicenseCheckRequest(
                license_id="lic-1",
                instance_id="inst-1",
                product="noctisapi",
                version="1.0",
            ))

        assert result.license_generation is None
