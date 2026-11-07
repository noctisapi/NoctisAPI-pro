from __future__ import annotations

import pytest

from control_center.ports import DeploymentTarget
from control_center.provider_adapters import HetznerDeploymentAdapter, ProviderAdapterError


def test_hetzner_adapter_observes_with_injected_transport_and_never_mutates() -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    def transport(url: str, headers: dict[str, str]) -> dict[str, object]:
        calls.append((url, headers))
        return {
            "server": {
                "status": "running",
                "datacenter": {"location": {"name": "nbg1"}},
            }
        }

    adapter = HetznerDeploymentAdapter(
        "test-token",
        transport=transport,
        base_url="https://provider.test/v1",
    )
    target = DeploymentTarget("dep-1", "tenant-1", "hetzner", "fsn1", "server/42")

    observation = adapter.observe(target)
    result = adapter.execute(target, "deploy", {})

    assert observation.deployment_id == "dep-1"
    assert observation.state == "active"
    assert observation.region == "nbg1"
    assert result.accepted is False
    assert len(calls) == 1
    assert calls[0][0] == "https://provider.test/v1/servers/server%2F42"
    assert calls[0][1]["Authorization"] == "Bearer test-token"


def test_hetzner_adapter_fails_closed_without_resource_reference() -> None:
    adapter = HetznerDeploymentAdapter("test-token", transport=lambda url, headers: {})
    with pytest.raises(ProviderAdapterError, match="provider_ref"):
        adapter.observe(DeploymentTarget("dep-1", "tenant-1", "hetzner", "fsn1"))


def test_hetzner_adapter_rejects_non_https_base_url_and_bad_response() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        HetznerDeploymentAdapter("test-token", base_url="http://provider.test/v1")

    adapter = HetznerDeploymentAdapter("test-token", transport=lambda url, headers: {"server": {}})
    with pytest.raises(ProviderAdapterError, match="status"):
        adapter.observe(DeploymentTarget("dep-1", "tenant-1", "hetzner", "fsn1", "server-1"))
