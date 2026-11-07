"""NOC-040: versioned entitlement contract, no billing or infrastructure."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from honey_licensing.entitlements import (
    EntitlementValidationError,
    EntitlementDocument,
    evaluate,
)


START = "2026-01-01T00:00:00Z"


def _doc(**overrides):
    value = {
        "schema_version": 1,
        "plan_id": "managed-pro",
        "mode": "managed",
        "features": ["cases", "analytics"],
        "quotas": {"max_cases": 10},
        "starts_at": START,
    }
    value.update(overrides)
    return EntitlementDocument.from_mapping(value)


def test_document_round_trips_without_billing_or_user_permissions():
    document = _doc()
    assert document.to_mapping() == {
        "schema_version": 1,
        "plan_id": "managed-pro",
        "mode": "managed",
        "features": ["analytics", "cases"],
        "quotas": {"max_cases": 10},
        "starts_at": START,
    }


def test_features_and_quotas_are_evaluated_locally():
    document = _doc()
    now = datetime(2026, 2, 1, tzinfo=timezone.utc)
    assert evaluate(document, "cases", now=now, usage=9, quota_name="max_cases").allowed
    assert evaluate(document, "cases", now=now, usage=10, quota_name="max_cases").reason == "quota_exceeded"
    assert evaluate(document, "replay", now=now).reason == "feature_not_entitled"


@pytest.mark.parametrize("field", ["billing_provider", "payment_status", "subscription_id", "user_roles", "permissions"])
def test_billing_and_user_permissions_are_not_entitlement_fields(field):
    with pytest.raises(EntitlementValidationError, match="must not contain"):
        _doc(**{field: "anything"})


def test_schema_rejects_unknown_feature_and_bad_dates():
    with pytest.raises(EntitlementValidationError, match="unknown entitlement"):
        _doc(features=["not_a_feature"])
    with pytest.raises(EntitlementValidationError, match="timezone"):
        _doc(starts_at="2026-01-01T00:00:00")


def test_expiration_and_mode_are_explicit():
    document = _doc(expires_at="2026-02-01T00:00:00Z")
    assert evaluate(document, "cases", now=datetime(2026, 2, 1, tzinfo=timezone.utc)).reason == "expired"
    with pytest.raises(EntitlementValidationError, match="managed or self_hosted"):
        _doc(mode="paid")
