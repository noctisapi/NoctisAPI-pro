from __future__ import annotations

import pytest

from control_center.ports import DeploymentTarget
from control_center.provider_adapters import CloudflareTunnelDeploymentAdapter, ProviderAdapterError


def test_cloudflare_tunnel_adapter_observes_with_injected_transport() -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    def transport(url: str, headers: dict[str, str]) -> dict[str, object]:
        calls.append((url, headers))
        return {"result": {"status": "healthy"}}

    adapter = CloudflareTunnelDeploymentAdapter(
        "test-token",
        "account/1",
        transport=transport,
        base_url="https://provider.test/client/v4",
    )
    target = DeploymentTarget("dep-1", "tenant-1", "cloudflare", "global", "tunnel/42")

    observation = adapter.observe(target)
    result = adapter.execute(target, "teardown", {})

    assert observation.state == "active"
    assert result.accepted is False
    assert len(calls) == 1
    assert calls[0][0] == "https://provider.test/client/v4/accounts/account%2F1/cfd_tunnel/tunnel%2F42"
    assert calls[0][1]["Authorization"] == "Bearer test-token"


def test_cloudflare_tunnel_adapter_maps_unhealthy_status_and_fails_closed() -> None:
    adapter = CloudflareTunnelDeploymentAdapter(
        "test-token",
        "account-1",
        transport=lambda url, headers: {"result": {"status": "down"}},
    )
    assert adapter.observe(DeploymentTarget("dep-1", "tenant-1", "cloudflare", "global", "tunnel-1")).state == "stale"

    with pytest.raises(ProviderAdapterError, match="provider_ref"):
        adapter.observe(DeploymentTarget("dep-1", "tenant-1", "cloudflare", "global"))
