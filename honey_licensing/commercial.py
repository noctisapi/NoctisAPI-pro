"""Pure commercial lifecycle and billing contracts (NOC-043--045).

These objects deliberately have no payment SDK or infrastructure side effect.
They make webhook handling, suspension/termination safety, idempotency and
plan-change history testable before a provider is selected.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from typing import Any, Callable, Mapping, Optional


class CommercialState(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class CommercialTransitionError(ValueError):
    """An invalid or insufficiently approved commercial transition."""


@dataclass(frozen=True)
class CommercialRecord:
    state: CommercialState = CommercialState.PENDING
    changed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notice_until: Optional[datetime] = None
    retention_until: Optional[datetime] = None
    last_event_id: Optional[str] = None


def transition(
    record: CommercialRecord,
    event: str,
    *,
    now: Optional[datetime] = None,
    event_id: Optional[str] = None,
    grace_days: int = 7,
    retention_days: int = 30,
    approved: bool = False,
) -> CommercialRecord:
    """Apply one explicit commercial event without deleting customer data."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    action = str(event or "").strip().lower()
    state = record.state
    if action in {"webhook_lost", "reconcile_pending"}:
        return replace(record, last_event_id=event_id or record.last_event_id)
    if state == CommercialState.TERMINATED:
        raise CommercialTransitionError("terminated is terminal")
    if action == "activate":
        if state not in {CommercialState.PENDING, CommercialState.PAST_DUE, CommercialState.SUSPENDED}:
            raise CommercialTransitionError(f"cannot activate from {state.value}")
        return replace(record, state=CommercialState.ACTIVE, changed_at=current, notice_until=None, last_event_id=event_id)
    if action == "payment_failed":
        if state not in {CommercialState.ACTIVE, CommercialState.PENDING}:
            raise CommercialTransitionError(f"cannot mark payment failed from {state.value}")
        return replace(
            record,
            state=CommercialState.PAST_DUE,
            changed_at=current,
            notice_until=current + timedelta(days=max(0, grace_days)),
            last_event_id=event_id,
        )
    if action == "suspend":
        if state != CommercialState.PAST_DUE:
            raise CommercialTransitionError(f"suspend requires past_due, found {state.value}")
        return replace(record, state=CommercialState.SUSPENDED, changed_at=current, last_event_id=event_id)
    if action == "terminate":
        if not approved:
            raise CommercialTransitionError("termination requires explicit approval")
        if state not in {CommercialState.SUSPENDED, CommercialState.PAST_DUE}:
            raise CommercialTransitionError(f"cannot terminate from {state.value}")
        return replace(
            record,
            state=CommercialState.TERMINATED,
            changed_at=current,
            retention_until=current + timedelta(days=max(0, retention_days)),
            last_event_id=event_id,
        )
    raise CommercialTransitionError(f"unknown commercial event: {action}")


@dataclass(frozen=True)
class BillingEvent:
    event_id: str
    provider: str
    event_type: str
    billing_reference: str
    occurred_at: datetime
    payload: Mapping[str, Any]

    def canonical_payload(self) -> bytes:
        return json.dumps(dict(self.payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify an HMAC webhook without parsing or storing payment data."""
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    supplied = str(signature or "").strip().removeprefix("sha256=")
    return bool(secret) and hmac.compare_digest(expected, supplied)


@dataclass(frozen=True)
class BillingApplyResult:
    event_id: str
    status: str  # applied | duplicate | failed
    detail: str


class BillingEventLedger:
    """Small idempotency ledger; production persistence belongs to CC/NOC-046."""

    def __init__(self) -> None:
        self._events: dict[str, BillingApplyResult] = {}

    def apply(
        self,
        event: BillingEvent,
        handler: Callable[[BillingEvent], None],
    ) -> BillingApplyResult:
        previous = self._events.get(event.event_id)
        if previous is not None:
            return BillingApplyResult(event.event_id, "duplicate", "event already processed")
        try:
            handler(event)
        except Exception:
            result = BillingApplyResult(event.event_id, "failed", "handler failed; reconciliation required")
            self._events[event.event_id] = result
            return result
        result = BillingApplyResult(event.event_id, "applied", "event applied once")
        self._events[event.event_id] = result
        return result


@dataclass(frozen=True)
class PlanChange:
    change_id: str
    deployment_id: str
    from_plan: str
    to_plan: str
    removed_features: frozenset[str]
    quota_reductions: Mapping[str, tuple[int, int]]
    created_at: datetime
    approved: bool = False

    @property
    def requires_confirmation(self) -> bool:
        return bool(self.removed_features or self.quota_reductions)


def plan_change(
    *,
    change_id: str,
    deployment_id: str,
    old_plan: Mapping[str, Any],
    new_plan: Mapping[str, Any],
    now: Optional[datetime] = None,
    approved: bool = False,
) -> PlanChange:
    old_features = {str(x).strip().lower() for x in old_plan.get("features", [])}
    new_features = {str(x).strip().lower() for x in new_plan.get("features", [])}
    old_quotas = {str(k): int(v) for k, v in (old_plan.get("quotas") or {}).items()}
    new_quotas = {str(k): int(v) for k, v in (new_plan.get("quotas") or {}).items()}
    reductions = {
        name: (old_value, new_quotas[name])
        for name, old_value in old_quotas.items()
        if name in new_quotas and new_quotas[name] < old_value
    }
    result = PlanChange(
        change_id=change_id,
        deployment_id=deployment_id,
        from_plan=str(old_plan.get("plan_id") or ""),
        to_plan=str(new_plan.get("plan_id") or ""),
        removed_features=frozenset(old_features - new_features),
        quota_reductions=reductions,
        created_at=(now or datetime.now(timezone.utc)).astimezone(timezone.utc),
        approved=approved,
    )
    if result.requires_confirmation and not approved:
        raise CommercialTransitionError("downgrade or entitlement reduction requires explicit approval")
    return result
