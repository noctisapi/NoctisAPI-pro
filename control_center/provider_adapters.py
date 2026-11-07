"""Read-only provider adapters with injectable HTTP transport.

The default transport is intentionally small and uses the standard library.
Tests and a future worker may inject a client instead; no provider SDK or
network call is created at import time.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .ports import AdapterResult, DeploymentOperation, DeploymentTarget, ProviderObservation

JsonTransport = Callable[[str, Mapping[str, str]], Mapping[str, object]]


class ProviderAdapterError(RuntimeError):
    """Raised when a provider response cannot be trusted as an observation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _urllib_get_json(url: str, headers: Mapping[str, str]) -> Mapping[str, object]:
    request = Request(url, headers=dict(headers), method="GET")
    try:
        with urlopen(request, timeout=10) as response:  # nosec B310 - URL is adapter-configured
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ProviderAdapterError(f"provider request failed: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ProviderAdapterError("provider response must be a JSON object")
    return payload


class HetznerDeploymentAdapter:
    """Observe a Hetzner Cloud server without enabling mutations."""

    _STATUS_MAP = {
        "initializing": "provisioning",
        "starting": "provisioning",
        "running": "active",
        "stopping": "suspended",
        "off": "suspended",
        "migrating": "provisioning",
        "rebuilding": "provisioning",
        "deleting": "terminated",
        "unknown": "stale",
    }

    def __init__(
        self,
        token: str,
        *,
        transport: JsonTransport | None = None,
        base_url: str = "https://api.hetzner.cloud/v1",
    ) -> None:
        if not token.strip():
            raise ValueError("Hetzner API token is required")
        if not base_url.startswith("https://"):
            raise ValueError("Hetzner API base URL must use HTTPS")
        self._headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self._transport = transport or _urllib_get_json
        self._base_url = base_url.rstrip("/")

    def observe(self, target: DeploymentTarget) -> ProviderObservation:
        if target.provider.strip().lower() != "hetzner":
            raise ProviderAdapterError(f"adapter cannot observe provider {target.provider}")
        if not target.provider_ref or not target.provider_ref.strip():
            raise ProviderAdapterError("Hetzner observation requires provider_ref")
        payload = self._transport(
            f"{self._base_url}/servers/{quote(target.provider_ref.strip(), safe='')}",
            self._headers,
        )
        server = payload.get("server")
        if not isinstance(server, Mapping):
            raise ProviderAdapterError("Hetzner response has no server object")
        raw_status = server.get("status")
        if not isinstance(raw_status, str):
            raise ProviderAdapterError("Hetzner server status is missing")
        state = self._STATUS_MAP.get(raw_status.lower(), "stale")
        datacenter = server.get("datacenter")
        region = target.region
        if isinstance(datacenter, Mapping):
            location = datacenter.get("location")
            if isinstance(location, Mapping) and isinstance(location.get("name"), str) and location["name"].strip():
                region = location["name"].strip()
        return ProviderObservation(
            deployment_id=target.deployment_id,
            provider="hetzner",
            region=region,
            state=state,
            observed_at=_now(),
        )

    def execute(
        self,
        target: DeploymentTarget,
        operation: DeploymentOperation,
        parameters: Mapping[str, object],
    ) -> AdapterResult:
        """Keep the first adapter read-only even if called accidentally."""

        return AdapterResult(
            operation=operation,
            accepted=False,
            message="Hetzner adapter is observation-only; mutations are disabled",
        )
