"""NOC-043--045: commercial states, billing idempotency and plan changes."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from honey_licensing.commercial import (
    BillingEvent,
    BillingEventLedger,
    CommercialRecord,
    CommercialState,
    CommercialTransitionError,
    plan_change,
    transition,
    verify_webhook_signature,
)


NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)


def test_commercial_state_distinguishes_past_due_suspended_and_terminated():
    record = transition(CommercialRecord(), "activate", now=NOW)
    record = transition(record, "payment_failed", now=NOW, event_id="evt-1")
    assert record.state == CommercialState.PAST_DUE
    assert record.notice_until is not None
    record = transition(record, "suspend", now=NOW, event_id="evt-2")
    assert record.state == CommercialState.SUSPENDED
    with pytest.raises(CommercialTransitionError, match="approval"):
        transition(record, "terminate", now=NOW)
    terminated = transition(record, "terminate", now=NOW, approved=True, event_id="evt-3")
    assert terminated.state == CommercialState.TERMINATED
    assert terminated.retention_until is not None


def test_lost_webhook_does_not_change_state_or_delete_data():
    record = CommercialRecord(state=CommercialState.ACTIVE)
    result = transition(record, "webhook_lost", now=NOW, event_id="evt-lost")
    assert result.state == CommercialState.ACTIVE
    assert result.last_event_id == "evt-lost"


def test_webhook_signature_and_idempotency():
    raw = b'{"id":"evt-1","type":"invoice.paid"}'
    import hashlib
    import hmac
    signature = hmac.new(b"secret", raw, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(raw, "sha256=" + signature, "secret")
    assert not verify_webhook_signature(raw, signature[:-1] + "0", "secret")

    event = BillingEvent("evt-1", "provider", "invoice.paid", "cus-1", NOW, {"status": "paid"})
    ledger = BillingEventLedger()
    applied = []
    assert ledger.apply(event, lambda value: applied.append(value.event_id)).status == "applied"
    assert ledger.apply(event, lambda value: applied.append(value.event_id)).status == "duplicate"
    assert applied == ["evt-1"]


def test_failed_billing_event_is_visible_for_manual_reconciliation():
    event = BillingEvent("evt-fail", "provider", "invoice.paid", "cus-1", NOW, {})
    result = BillingEventLedger().apply(event, lambda _: (_ for _ in ()).throw(RuntimeError("no")))
    assert result.status == "failed"
    assert "reconciliation" in result.detail


def test_plan_downgrade_requires_approval_and_is_reversible_as_history():
    old = {"plan_id": "managed-pro", "features": ["cases", "analytics"], "quotas": {"max_cases": 100}}
    new = {"plan_id": "managed-core", "features": ["cases"], "quotas": {"max_cases": 10}}
    with pytest.raises(CommercialTransitionError, match="approval"):
        plan_change(change_id="chg-1", deployment_id="dep-1", old_plan=old, new_plan=new)
    change = plan_change(
        change_id="chg-1", deployment_id="dep-1", old_plan=old, new_plan=new,
        now=NOW, approved=True,
    )
    assert change.removed_features == frozenset({"analytics"})
    assert change.quota_reductions == {"max_cases": (100, 10)}
    assert change.approved is True
