"""Read-only signed billing adapter boundary.

This adapter intentionally models a provider-neutral JSON API. A concrete
provider can supply the transport later; the Control Center still owns event
verification, redaction and the commercial-state allow-list.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from urllib.parse import quote

from honey_licensing.commercial import verify_webhook_signature

from .model import COMMERCIAL_STATES
from .ports import BillingEvent, BillingSubscriptionSnapshot
from .provider_adapters import JsonTransport, ProviderAdapterError, _urllib_get_json
from .security import sanitize_audit_details

_CARD_KEYS = frozenset({"card_number", "pan", "cvv", "cvc", "expiration", "expiry", "payment_method_details"})


class BillingAdapterError(ProviderAdapterError):
    """Raised when billing data or a webhook signature is not trustworthy."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _contains_card_data(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in _CARD_KEYS or _contains_card_data(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_card_data(item) for item in value)
    return False


class SignedJsonBillingAdapter:
    """Fetch subscription state and verify canonical JSON billing events."""

    def __init__(
        self,
        provider: str,
        token: str,
        webhook_secret: str,
        *,
        transport: JsonTransport | None = None,
        base_url: str = "https://billing.invalid/v1",
    ) -> None:
        if not provider.strip():
            raise ValueError("billing provider is required")
        if not token.strip():
            raise ValueError("billing API token is required")
        if not webhook_secret.strip():
            raise ValueError("billing webhook secret is required")
        if not base_url.startswith("https://"):
            raise ValueError("billing API base URL must use HTTPS")
        self._provider = provider.strip().lower()
        self._token = token.strip()
        self._webhook_secret = webhook_secret
        self._transport = transport or _urllib_get_json
        self._base_url = base_url.rstrip("/")

    def subscription(self, subscription_id: str) -> BillingSubscriptionSnapshot:
        if not subscription_id.strip():
            raise BillingAdapterError("subscription ID is required")
        payload = self._transport(
            f"{self._base_url}/subscriptions/{quote(subscription_id.strip(), safe='')}",
            {"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
        )
        record = payload.get("subscription")
        if not isinstance(record, Mapping):
            raise BillingAdapterError("billing response has no subscription object")
        plan_code = record.get("plan_code", record.get("plan"))
        state = record.get("commercial_state", record.get("status"))
        if not isinstance(plan_code, str) or not plan_code.strip():
            raise BillingAdapterError("billing subscription plan is missing")
        if not isinstance(state, str) or state not in COMMERCIAL_STATES:
            raise BillingAdapterError("billing subscription state is invalid")
        billing_ref = record.get("billing_ref", record.get("id"))
        if billing_ref is not None and not isinstance(billing_ref, str):
            raise BillingAdapterError("billing reference must be text")
        return BillingSubscriptionSnapshot(
            subscription_id=subscription_id.strip(),
            plan_code=plan_code.strip(),
            commercial_state=state,
            billing_ref=billing_ref,
            observed_at=_now(),
        )

    def verify_event(self, payload: Mapping[str, object], signature: str) -> BillingEvent:
        if not isinstance(payload, Mapping) or _contains_card_data(payload):
            raise BillingAdapterError("billing event contains forbidden payment data")
        canonical = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not verify_webhook_signature(canonical, signature, self._webhook_secret):
            raise BillingAdapterError("billing event signature is invalid")
        event_id = payload.get("id", payload.get("event_id"))
        subscription_id = payload.get("subscription_id")
        event_type = payload.get("type", payload.get("event_type"))
        applied_state = payload.get("commercial_state", payload.get("status"))
        if not all(isinstance(value, str) and value.strip() for value in (event_id, subscription_id, event_type)):
            raise BillingAdapterError("billing event identity is incomplete")
        if applied_state is not None and (not isinstance(applied_state, str) or applied_state not in COMMERCIAL_STATES):
            raise BillingAdapterError("billing event state is invalid")
        return BillingEvent(
            external_event_id=event_id.strip(),
            subscription_id=subscription_id.strip(),
            provider=self._provider,
            event_type=event_type.strip(),
            applied_state=applied_state,
            payload=sanitize_audit_details(dict(payload)),
        )
