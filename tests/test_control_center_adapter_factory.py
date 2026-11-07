from __future__ import annotations

import pytest

from control_center.adapter_factory import AdapterConfiguration, AdapterConfigurationError, build_adapter_bundle


class _Secrets:
    def __init__(self, values: dict[str, str]) -> None:
        self.values_by_name = values
        self.requests: list[tuple[str, ...]] = []

    def get(self, name: str) -> str:
        return self.values_by_name[name]

    def rotate(self, name: str) -> None:  # pragma: no cover
        raise AssertionError("factory must not rotate secrets")

    def values(self, names):
        requested = tuple(names)
        self.requests.append(requested)
        return {name: self.values_by_name[name] for name in requested}


def test_factory_is_disabled_by_default_and_does_not_read_secrets() -> None:
    secrets = _Secrets({})
    bundle = build_adapter_bundle(AdapterConfiguration(), secrets)
    assert bundle.deployments.providers() == ()
    assert dict(bundle.billing) == {}
    assert secrets.requests == []


def test_factory_builds_only_enabled_adapters_from_secret_manager() -> None:
    secrets = _Secrets(
        {
            "HETZNER_API_TOKEN": "hetzner-token",
            "CLOUDFLARE_API_TOKEN": "cloudflare-token",
            "BILLING_API_TOKEN": "billing-token",
            "BILLING_WEBHOOK_SECRET": "webhook-secret",
        }
    )
    config = AdapterConfiguration(
        hetzner_enabled=True,
        cloudflare_enabled=True,
        cloudflare_account_id="account-1",
        billing_provider="test-billing",
    )

    bundle = build_adapter_bundle(config, secrets, transport=lambda url, headers: {})

    assert bundle.deployments.providers() == ("cloudflare", "hetzner")
    assert tuple(bundle.billing) == ("test-billing",)
    assert secrets.requests == [
        ("HETZNER_API_TOKEN", "CLOUDFLARE_API_TOKEN", "BILLING_API_TOKEN", "BILLING_WEBHOOK_SECRET")
    ]


def test_factory_fails_closed_when_cloudflare_account_is_missing() -> None:
    with pytest.raises(AdapterConfigurationError, match="account ID"):
        build_adapter_bundle(
            AdapterConfiguration(cloudflare_enabled=True),
            _Secrets({"CLOUDFLARE_API_TOKEN": "token"}),
        )


def test_configuration_from_env_contains_names_not_secret_values() -> None:
    config = AdapterConfiguration.from_env(
        {
            "NOCTISAPI_ADAPTER_HETZNER_ENABLED": "true",
            "NOCTISAPI_ADAPTER_HETZNER_TOKEN_SECRET": "secret/hetzner",
            "NOCTISAPI_ADAPTER_CLOUDFLARE_ACCOUNT_ID": "account-1",
        }
    )
    assert config.hetzner_enabled is True
    assert config.hetzner_token_secret == "secret/hetzner"
    assert not hasattr(config, "hetzner_token")
