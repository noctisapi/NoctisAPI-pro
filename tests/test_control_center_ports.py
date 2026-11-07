from control_center.ports import (
    AdapterResult,
    BillingEvent,
    BillingSubscriptionSnapshot,
    DeploymentTarget,
    ProviderObservation,
)


def test_provider_contracts_are_typed_and_immutable() -> None:
    target = DeploymentTarget("dep_a", "tenant_a", "hetzner", "fsn1")
    observation = ProviderObservation("dep_a", "hetzner", "fsn1", "active", "2026-11-07T00:00:00Z")
    result = AdapterResult("status", True, external_ref="server-1")
    assert target.tenant_id == "tenant_a"
    assert observation.state == "active"
    assert result.operation == "status"


def test_billing_contract_contains_no_payment_fields() -> None:
    snapshot = BillingSubscriptionSnapshot("sub_a", "pro", "active", "cus_ref", "2026-11-07T00:00:00Z")
    event = BillingEvent("evt_a", "sub_a", "provider", "invoice.paid", "active", {"amount": 100})
    assert snapshot.billing_ref == "cus_ref"
    assert event.payload["amount"] == 100
    assert "card_number" not in event.payload
