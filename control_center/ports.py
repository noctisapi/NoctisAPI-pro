"""Provider ports for the Control Plane.

These are contracts only. Implementations belong in adapters and must be
injected into a worker; HTTP requests never select a provider SDK or shell
command directly.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol


DeploymentOperation = Literal[
    "deploy", "status", "verify", "upgrade", "backup", "suspend", "teardown", "reconcile",
]


@dataclass(frozen=True)
class DeploymentTarget:
    deployment_id: str
    tenant_id: str
    provider: str
    region: str
    provider_ref: str | None = None


@dataclass(frozen=True)
class ProviderObservation:
    deployment_id: str
    provider: str
    region: str
    state: str
    observed_at: str


@dataclass(frozen=True)
class AdapterResult:
    operation: DeploymentOperation
    accepted: bool
    external_ref: str | None = None
    message: str = ""


class DeploymentAdapter(Protocol):
    def observe(self, target: DeploymentTarget) -> ProviderObservation: ...
    def execute(self, target: DeploymentTarget, operation: DeploymentOperation, parameters: Mapping[str, object]) -> AdapterResult: ...


@dataclass(frozen=True)
class BillingSubscriptionSnapshot:
    subscription_id: str
    plan_code: str
    commercial_state: str
    billing_ref: str | None
    observed_at: str


@dataclass(frozen=True)
class BillingEvent:
    external_event_id: str
    subscription_id: str
    provider: str
    event_type: str
    applied_state: str | None
    payload: Mapping[str, object]


class BillingAdapter(Protocol):
    def subscription(self, subscription_id: str) -> BillingSubscriptionSnapshot: ...
    def verify_event(self, payload: Mapping[str, object], signature: str) -> BillingEvent: ...
