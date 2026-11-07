"""Explicit, fail-closed construction of Control Center adapters."""

from __future__ import annotations

import os
from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping

from scripts.state_security import SecretManager

from .adapters import AdapterRegistry
from .billing_adapters import SignedJsonBillingAdapter
from .ports import BillingAdapter
from .provider_adapters import CloudflareTunnelDeploymentAdapter, HetznerDeploymentAdapter, JsonTransport


class AdapterConfigurationError(ValueError):
    """Raised when an adapter is enabled without complete non-secret config."""


def _flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AdapterConfiguration:
    """Non-secret adapter configuration; secret values never live here."""

    hetzner_enabled: bool = False
    hetzner_token_secret: str = "HETZNER_API_TOKEN"
    hetzner_base_url: str = "https://api.hetzner.cloud/v1"
    cloudflare_enabled: bool = False
    cloudflare_account_id: str = ""
    cloudflare_token_secret: str = "CLOUDFLARE_API_TOKEN"
    cloudflare_base_url: str = "https://api.cloudflare.com/client/v4"
    billing_provider: str = ""
    billing_token_secret: str = "BILLING_API_TOKEN"
    billing_webhook_secret: str = "BILLING_WEBHOOK_SECRET"
    billing_base_url: str = "https://billing.invalid/v1"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "AdapterConfiguration":
        values = os.environ if environ is None else environ
        return cls(
            hetzner_enabled=_flag(values.get("NOCTISAPI_ADAPTER_HETZNER_ENABLED")),
            hetzner_token_secret=values.get("NOCTISAPI_ADAPTER_HETZNER_TOKEN_SECRET", cls.hetzner_token_secret),
            hetzner_base_url=values.get("NOCTISAPI_ADAPTER_HETZNER_BASE_URL", cls.hetzner_base_url),
            cloudflare_enabled=_flag(values.get("NOCTISAPI_ADAPTER_CLOUDFLARE_ENABLED")),
            cloudflare_account_id=values.get("NOCTISAPI_ADAPTER_CLOUDFLARE_ACCOUNT_ID", ""),
            cloudflare_token_secret=values.get("NOCTISAPI_ADAPTER_CLOUDFLARE_TOKEN_SECRET", cls.cloudflare_token_secret),
            cloudflare_base_url=values.get("NOCTISAPI_ADAPTER_CLOUDFLARE_BASE_URL", cls.cloudflare_base_url),
            billing_provider=values.get("NOCTISAPI_ADAPTER_BILLING_PROVIDER", ""),
            billing_token_secret=values.get("NOCTISAPI_ADAPTER_BILLING_TOKEN_SECRET", cls.billing_token_secret),
            billing_webhook_secret=values.get("NOCTISAPI_ADAPTER_BILLING_WEBHOOK_SECRET", cls.billing_webhook_secret),
            billing_base_url=values.get("NOCTISAPI_ADAPTER_BILLING_BASE_URL", cls.billing_base_url),
        )


@dataclass(frozen=True)
class AdapterBundle:
    deployments: AdapterRegistry
    billing: Mapping[str, BillingAdapter]


def build_adapter_bundle(
    config: AdapterConfiguration,
    secrets: SecretManager | None = None,
    *,
    transport: JsonTransport | None = None,
) -> AdapterBundle:
    """Build only explicitly enabled adapters from an injected secret manager."""

    secret_names: list[str] = []
    if config.hetzner_enabled:
        secret_names.append(config.hetzner_token_secret)
    if config.cloudflare_enabled:
        if not config.cloudflare_account_id.strip():
            raise AdapterConfigurationError("Cloudflare account ID is required when enabled")
        secret_names.append(config.cloudflare_token_secret)
    if config.billing_provider.strip():
        secret_names.extend((config.billing_token_secret, config.billing_webhook_secret))

    if secret_names and secrets is None:
        raise AdapterConfigurationError("a secret manager is required for enabled adapters")
    secret_values = secrets.values(dict.fromkeys(secret_names)) if secret_names and secrets is not None else {}
    deployment_adapters: dict[str, object] = {}
    billing_adapters: dict[str, BillingAdapter] = {}

    if config.hetzner_enabled:
        deployment_adapters["hetzner"] = HetznerDeploymentAdapter(
            secret_values[config.hetzner_token_secret],
            transport=transport,
            base_url=config.hetzner_base_url,
        )
    if config.cloudflare_enabled:
        deployment_adapters["cloudflare"] = CloudflareTunnelDeploymentAdapter(
            secret_values[config.cloudflare_token_secret],
            config.cloudflare_account_id,
            transport=transport,
            base_url=config.cloudflare_base_url,
        )
    if config.billing_provider.strip():
        provider = config.billing_provider.strip().lower()
        billing_adapters[provider] = SignedJsonBillingAdapter(
            provider,
            secret_values[config.billing_token_secret],
            secret_values[config.billing_webhook_secret],
            transport=transport,
            base_url=config.billing_base_url,
        )

    return AdapterBundle(
        deployments=AdapterRegistry(deployment_adapters),
        billing=MappingProxyType(billing_adapters),
    )
