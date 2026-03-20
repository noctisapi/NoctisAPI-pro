"""Online license validation HTTP client.

Calls the licensing server's POST /v1/licenses/check endpoint.
No business logic here — only HTTP transport, retries, and typed request/response.

Configuration (all via environment variables, resolved by OnlineLicenseClient.from_env()):
  HP_LICENSING_SERVER_URL           Base URL of the licensing server (e.g. https://licenses.example.com)
  HP_ONLINE_CHECK_SECRET            Shared secret matching ONLINE_CHECK_SECRET on the server
  HP_ONLINE_CHECK_TIMEOUT_SECONDS   Per-request timeout (default: 10)
  HP_ONLINE_CHECK_MAX_RETRIES       Retries on 5xx/network errors (default: 2, excludes auth/404)
  HP_ONLINE_CHECK_RETRY_BACKOFF_S   Base backoff seconds between retries (default: 1.0)
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Literal, Optional

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed request / response
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LicenseCheckRequest:
    license_id: str
    instance_id: str
    product: str
    version: str
    instance_fingerprint: Optional[str] = None


@dataclass(frozen=True)
class LicenseCheckResponse:
    status: Literal["active", "revoked", "expired", "suspended", "reuse_limit_exceeded"]
    expires_at: Optional[str] = None
    grace_period_seconds: Optional[int] = None
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


class OnlineCheckError(RuntimeError):
    """Raised when the check fails due to network, timeout, or server error.

    This is NOT raised for valid license status responses (active/revoked/etc.).
    The caller should treat this as a connectivity problem and apply grace policy.
    """
    pass


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


_VALID_STATUSES = frozenset(("active", "revoked", "expired", "suspended", "reuse_limit_exceeded"))

# HTTP status codes that should not be retried (clear protocol-level errors)
_NO_RETRY_HTTP_STATUSES = frozenset((400, 401, 403, 404, 422, 501))


class OnlineLicenseClient:
    """HTTP client for online license validation.

    Thread-safe: creates a new httpx.Client per request (stateless).
    Handles retries with linear backoff on 5xx and network errors.
    Does NOT contain licensing business logic.
    """

    def __init__(
        self,
        *,
        base_url: str,
        shared_secret: str,
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._shared_secret = shared_secret
        self._timeout = max(1.0, float(timeout_seconds))
        self._max_retries = max(0, int(max_retries))
        self._retry_backoff = max(0.0, float(retry_backoff_seconds))

    def check(self, req: LicenseCheckRequest) -> LicenseCheckResponse:
        """Perform an online license check against the licensing server.

        Returns a LicenseCheckResponse on HTTP 200.
        Raises OnlineCheckError on network errors, timeouts, or unexpected HTTP responses.
        Never raises for valid license status values (active/revoked/expired/suspended).
        """
        url = f"{self._base_url}/v1/licenses/check"
        payload = {
            "license_id": req.license_id,
            "instance_id": req.instance_id,
            "product": req.product,
            "version": req.version,
        }
        if req.instance_fingerprint:
            payload["instance_fingerprint"] = req.instance_fingerprint
        headers = {
            "X-License-Check-Token": self._shared_secret,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        last_error: Optional[OnlineCheckError] = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                sleep_s = self._retry_backoff * attempt
                logger.debug("license_online_client: backoff attempt=%d sleep=%.1fs", attempt, sleep_s)
                time.sleep(sleep_s)

            try:
                with httpx.Client(timeout=self._timeout) as client:
                    resp = client.post(url, json=payload, headers=headers)

                if resp.status_code == 200:
                    return self._parse_response(resp)

                if resp.status_code in _NO_RETRY_HTTP_STATUSES:
                    raise OnlineCheckError(
                        f"http_{resp.status_code}: {resp.text[:300]}"
                    )

                # 5xx or unexpected: retryable
                last_error = OnlineCheckError(f"http_{resp.status_code}: {resp.text[:200]}")
                logger.warning(
                    "license_online_client: retryable error attempt=%d/%d status=%d url=%s",
                    attempt + 1, self._max_retries + 1, resp.status_code, url,
                )

            except OnlineCheckError:
                raise

            except httpx.TimeoutException as exc:
                last_error = OnlineCheckError(f"timeout: {exc}")
                logger.warning(
                    "license_online_client: timeout attempt=%d/%d url=%s",
                    attempt + 1, self._max_retries + 1, url,
                )

            except httpx.RequestError as exc:
                last_error = OnlineCheckError(f"network: {exc}")
                logger.warning(
                    "license_online_client: network_error attempt=%d/%d url=%s error=%s",
                    attempt + 1, self._max_retries + 1, url, exc,
                )

        raise last_error or OnlineCheckError("unknown error after retries")

    def _parse_response(self, resp: httpx.Response) -> LicenseCheckResponse:
        try:
            data = resp.json()
        except Exception as exc:
            raise OnlineCheckError(f"invalid json in response: {exc}") from exc

        if not isinstance(data, dict):
            raise OnlineCheckError(f"unexpected response shape: {type(data)}")

        status = str(data.get("status") or "").strip().lower()
        if status not in _VALID_STATUSES:
            raise OnlineCheckError(f"unexpected status value: {status!r}")

        raw_grace = data.get("grace_period_seconds")
        grace: Optional[int] = None
        if raw_grace is not None:
            try:
                grace = int(raw_grace)
            except (TypeError, ValueError):
                pass

        return LicenseCheckResponse(
            status=status,  # type: ignore[arg-type]
            expires_at=data.get("expires_at") or None,
            grace_period_seconds=grace,
            reason=data.get("reason") or None,
        )

    # ---------------------------------------------------------------------------
    # Factory
    # ---------------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> Optional["OnlineLicenseClient"]:
        """Build from environment variables. Returns None if HP_LICENSING_SERVER_URL is not set."""
        base_url = (os.getenv("HP_LICENSING_SERVER_URL") or "").strip()
        if not base_url:
            return None

        shared_secret = (os.getenv("HP_ONLINE_CHECK_SECRET") or "").strip()
        if not shared_secret:
            logger.warning(
                "license_online_client: HP_LICENSING_SERVER_URL is set but HP_ONLINE_CHECK_SECRET is empty; "
                "online checks are disabled"
            )
            return None

        try:
            timeout = float(os.getenv("HP_ONLINE_CHECK_TIMEOUT_SECONDS") or "10")
        except (ValueError, TypeError):
            timeout = 10.0

        try:
            max_retries = int(os.getenv("HP_ONLINE_CHECK_MAX_RETRIES") or "2")
        except (ValueError, TypeError):
            max_retries = 2

        try:
            backoff = float(os.getenv("HP_ONLINE_CHECK_RETRY_BACKOFF_S") or "1.0")
        except (ValueError, TypeError):
            backoff = 1.0

        return cls(
            base_url=base_url,
            shared_secret=shared_secret,
            timeout_seconds=timeout,
            max_retries=max_retries,
            retry_backoff_seconds=backoff,
        )
