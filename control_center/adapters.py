"""Provider adapter registry for the Control Center worker.

The registry deliberately contains no provider SDKs. Deployments inject
adapters at process startup, keeping HTTP routes and queued job payloads from
selecting arbitrary clients or commands.
"""

from __future__ import annotations

from collections.abc import Mapping

from .ports import DeploymentAdapter


class AdapterUnavailableError(LookupError):
    """Raised when no adapter has been configured for a provider."""


class AdapterRegistry:
    """Resolve explicitly configured provider adapters by stable name."""

    def __init__(self, adapters: Mapping[str, DeploymentAdapter] | None = None) -> None:
        self._adapters = {
            name.strip().lower(): adapter
            for name, adapter in (adapters or {}).items()
            if isinstance(name, str) and name.strip()
        }

    def get(self, provider: str) -> DeploymentAdapter:
        key = provider.strip().lower()
        if not key or key not in self._adapters:
            raise AdapterUnavailableError(provider)
        return self._adapters[key]

    def providers(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))
