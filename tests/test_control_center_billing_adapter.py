from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from control_center.billing_adapters import BillingAdapterError, SignedJsonBillingAdapter


def _signature(payload: dict[str, object], secret: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256=" + hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def test_billing_adapter_reads_subscription_and_verifies_event_without_card_data() -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    def transport(url: str, headers: dict[str, str]) -> dict[str, object]:
        calls.append((url, headers))
        return {"subscription": {"id": "sub_1", "plan_code": "managed-pro", "status": "active"}}

    adapter = SignedJsonBillingAdapter(
        "test-billing",
        "api-token",
        "webhook-secret",
        transport=transport,
        base_url="https://billing.test/v1",
    )
    snapshot = adapter.subscription("sub_1")
    payload = {"id": "evt_1", "type": "subscription.active", "subscription_id": "sub_1", "status": "active"}
    event = adapter.verify_event(payload, _signature(payload, "webhook-secret"))

    assert snapshot.plan_code == "managed-pro"
    assert snapshot.commercial_state == "active"
    assert event.external_event_id == "evt_1"
    assert event.provider == "test-billing"
    assert len(calls) == 1
    assert calls[0][1]["Authorization"] == "Bearer api-token"


def test_billing_adapter_rejects_invalid_signature_card_data_and_unknown_state() -> None:
    adapter = SignedJsonBillingAdapter("test-billing", "api-token", "webhook-secret", transport=lambda url, headers: {})
    payload = {"id": "evt_1", "type": "invoice.paid", "subscription_id": "sub_1", "status": "active"}
    with pytest.raises(BillingAdapterError, match="signature"):
        adapter.verify_event(payload, "sha256=invalid")
    card_payload = {**payload, "payment_method_details": {"card_number": "4111111111111111"}}
    with pytest.raises(BillingAdapterError, match="payment data"):
        adapter.verify_event(card_payload, _signature(card_payload, "webhook-secret"))
    unknown_state = {**payload, "status": "unknown"}
    with pytest.raises(BillingAdapterError, match="state"):
        adapter.verify_event(unknown_state, _signature(unknown_state, "webhook-secret"))


def test_billing_adapter_rejects_invalid_subscription_snapshot() -> None:
    adapter = SignedJsonBillingAdapter(
        "test-billing",
        "api-token",
        "webhook-secret",
        transport=lambda url, headers: {"subscription": {"plan_code": "managed-pro", "status": "unknown"}},
    )
    with pytest.raises(BillingAdapterError, match="state"):
        adapter.subscription("sub_1")
