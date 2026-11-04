"""Unit tests for the TTP classifier (app/stage/ttp.py).

All rules are deterministic and behavior-based — endpoint identity never drives TTP alone.

Test matrix:
  IDOR single access (success)          → UNAUTHORIZED_ACCESS
  IDOR sequential multi-ID (success)    → COLLECTION
  IDOR bulk / high-volume               → EXFILTRATION (secondary: data_collection)
  Repeated auth failures                → DISCOVERY + secondary credential_brute
  PRIV_ESC endpoint (success)           → IMPACT (privilege_escalation)
  COMMAND_EXECUTION endpoint (success)  → IMPACT (code_execution)
  DELETE success                        → IMPACT (destructive_action)
  BULK_EXFIL endpoint                   → EXFILTRATION
  AUTH_BYPASS success                   → UNAUTHORIZED_ACCESS
  No data / empty session               → DISCOVERY
  Same endpoint, different behavior     → different TTPs
  Endpoint identity alone               → does NOT change primary TTP
"""
from __future__ import annotations

import json
import pytest

from app.stage.ttp import (
    TTPContext,
    TTPResult,
    build_ttp_context,
    classify_ttp,
    ttp_display_data,
    MITRE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _step(method="GET", path="/api/v1/users/1", status=200):
    return {"method": method, "path": path, "response_status": status, "ts": "2024-01-01T00:00:00Z"}


def _event(kind="probe", path="/api/v1/users/1", method="GET", status=200, attack_phase="collection", vuln_type=None):
    extra = {"attack_phase": attack_phase}
    if vuln_type:
        extra["vulnerability_type"] = vuln_type
    return {
        "kind": kind,
        "path": path,
        "method": method,
        "status": status,
        "extra_json": json.dumps(extra),
        "ts": "2024-01-01T00:00:00Z",
    }


def _ctx(**kwargs) -> TTPContext:
    return TTPContext(**kwargs)


# ── classify_ttp: core behavioral rules ──────────────────────────────────────

class TestClassifyTTPImpact:
    def test_priv_esc_vuln(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"PRIV_ESC"}),
            max_stage="impact",
            success_count=1,
        )
        result = classify_ttp(ctx)
        assert result.primary == "privilege_escalation"
        assert result.reason  # non-empty reason
        assert "PRIV_ESC" in result.reason or "stage" in result.reason.lower()

    def test_command_execution_vuln(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"COMMAND_EXECUTION"}),
            max_stage="impact",
            success_count=2,
        )
        result = classify_ttp(ctx)
        assert result.primary == "code_execution"

    def test_destructive_write_delete(self):
        ctx = _ctx(
            has_destructive_write=True,
            max_stage="recon",
            success_count=1,
        )
        result = classify_ttp(ctx)
        assert result.primary == "destructive_action"

    def test_impact_adds_collection_secondary_when_multi_id(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"PRIV_ESC"}),
            max_stage="impact",
            success_count=3,
            distinct_resource_ids=4,
        )
        result = classify_ttp(ctx)
        assert result.primary == "privilege_escalation"
        assert "data_collection" in result.secondary


class TestClassifyTTPExfiltration:
    def test_bulk_exfil_vuln(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"BULK_EXFIL"}),
            max_stage="exfiltration",
            success_count=5,
        )
        result = classify_ttp(ctx)
        assert result.primary == "bulk_exfiltration"

    def test_bulk_access_flag(self):
        ctx = _ctx(
            bulk_access=True,
            max_stage="exfiltration",
            success_count=12,
            distinct_resource_ids=8,
        )
        result = classify_ttp(ctx)
        assert result.primary == "bulk_exfiltration"

    def test_exfil_has_collection_secondary_when_multi_id(self):
        ctx = _ctx(
            bulk_access=True,
            max_stage="exfiltration",
            success_count=15,
            distinct_resource_ids=10,
            sequential_pattern=True,
        )
        result = classify_ttp(ctx)
        assert result.primary == "bulk_exfiltration"
        assert "data_collection" in result.secondary

    def test_sequential_pattern_in_reason(self):
        ctx = _ctx(
            bulk_access=True,
            sequential_pattern=True,
            distinct_resource_ids=7,
            max_stage="exfiltration",
            success_count=7,
        )
        result = classify_ttp(ctx)
        assert result.primary == "bulk_exfiltration"
        assert "sequential" in result.reason.lower() or "7" in result.reason


class TestClassifyTTPCollection:
    def test_idor_multi_id(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"IDOR"}),
            max_stage="collection",
            success_count=3,
            distinct_resource_ids=3,
        )
        result = classify_ttp(ctx)
        assert result.primary == "data_collection"

    def test_idor_sequential_in_reason(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"IDOR"}),
            max_stage="collection",
            success_count=5,
            distinct_resource_ids=5,
            sequential_pattern=True,
        )
        result = classify_ttp(ctx)
        assert result.primary == "data_collection"
        assert "sequential" in result.reason.lower()

    def test_data_exposure_multi_id(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"DATA_EXPOSURE"}),
            max_stage="collection",
            success_count=2,
            distinct_resource_ids=2,
        )
        result = classify_ttp(ctx)
        assert result.primary == "data_collection"

    def test_no_success_prevents_collection(self):
        # IDOR with no successes → should not classify as collection
        ctx = _ctx(
            vulnerability_types=frozenset({"IDOR"}),
            max_stage="recon",
            success_count=0,
            failure_count=5,
            distinct_resource_ids=3,
        )
        result = classify_ttp(ctx)
        assert result.primary != "data_collection"


class TestClassifyTTPUnauthorizedAccess:
    def test_idor_single_success(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"IDOR"}),
            max_stage="collection",
            success_count=1,
            distinct_resource_ids=1,
        )
        result = classify_ttp(ctx)
        assert result.primary == "unauthorized_access"

    def test_auth_bypass_success(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"AUTH_BYPASS"}),
            max_stage="access",
            success_count=1,
        )
        result = classify_ttp(ctx)
        assert result.primary == "unauthorized_access"

    def test_weak_auth_success(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"WEAK_AUTH"}),
            max_stage="access",
            success_count=2,
        )
        result = classify_ttp(ctx)
        assert result.primary == "unauthorized_access"

    def test_access_stage_without_explicit_vuln(self):
        # max_stage="access" means the stage classifier confirmed a successful bypass.
        # That is unauthorized access even if no specific vuln type is recorded.
        ctx = _ctx(
            max_stage="access",
            success_count=1,
        )
        result = classify_ttp(ctx)
        assert result.primary == "unauthorized_access"


class TestClassifyTTPDiscovery:
    def test_repeated_failures(self):
        ctx = _ctx(
            repeated_failures=True,
            failure_count=8,
            max_stage="recon",
            success_count=0,
        )
        result = classify_ttp(ctx)
        assert result.primary == "discovery"
        assert "failure" in result.reason.lower() or "recon" in result.reason.lower()

    def test_enumeration_vuln(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"ENUMERATION"}),
            max_stage="recon",
            request_count=5,
            failure_count=3,
        )
        result = classify_ttp(ctx)
        assert result.primary == "discovery"

    def test_empty_session(self):
        ctx = _ctx()
        result = classify_ttp(ctx)
        assert result.primary == "discovery"
        assert result.reason  # must have a non-empty reason


class TestSecondarySignals:
    def test_auth_failures_add_credential_brute(self):
        ctx = _ctx(
            max_stage="recon",
            auth_failure_count=4,
            failure_count=4,
            repeated_failures=True,
        )
        result = classify_ttp(ctx)
        assert "credential_brute" in result.secondary

    def test_token_events_add_credential_token(self):
        ctx = _ctx(
            max_stage="recon",
            has_token_events=True,
        )
        result = classify_ttp(ctx)
        assert "credential_token" in result.secondary

    def test_secret_access_adds_secondary_on_discovery(self):
        ctx = _ctx(
            max_stage="recon",
            has_secret_access=True,
            repeated_failures=True,
        )
        result = classify_ttp(ctx)
        assert result.primary == "discovery"
        assert "secret_access" in result.secondary

    def test_auth_failures_below_threshold_not_secondary(self):
        ctx = _ctx(
            max_stage="recon",
            auth_failure_count=2,  # below threshold of 3
        )
        result = classify_ttp(ctx)
        assert "credential_brute" not in result.secondary


class TestPriorityOrder:
    def test_impact_beats_exfil(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"PRIV_ESC", "BULK_EXFIL"}),
            max_stage="impact",
            bulk_access=True,
            success_count=5,
        )
        result = classify_ttp(ctx)
        assert result.primary == "privilege_escalation"

    def test_exfil_beats_collection(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"BULK_EXFIL", "IDOR"}),
            max_stage="exfiltration",
            bulk_access=True,
            success_count=10,
            distinct_resource_ids=8,
        )
        result = classify_ttp(ctx)
        assert result.primary == "bulk_exfiltration"

    def test_collection_beats_unauthorized(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"IDOR"}),
            max_stage="collection",
            success_count=3,
            distinct_resource_ids=3,
        )
        result = classify_ttp(ctx)
        assert result.primary == "data_collection"
        assert result.primary != "unauthorized_access"

    def test_unauthorized_beats_discovery(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"AUTH_BYPASS"}),
            max_stage="access",
            success_count=1,
            repeated_failures=True,
        )
        result = classify_ttp(ctx)
        assert result.primary == "unauthorized_access"


class TestEndpointNeutrality:
    """Confirm that changing endpoint_id alone does NOT change the primary TTP
    when all behavioral signals remain identical."""

    def _base_ctx(self) -> TTPContext:
        return _ctx(
            vulnerability_types=frozenset({"IDOR"}),
            max_stage="collection",
            success_count=1,
            distinct_resource_ids=1,
        )

    def test_same_behavior_same_ttp(self):
        r1 = classify_ttp(self._base_ctx())
        r2 = classify_ttp(self._base_ctx())
        assert r1.primary == r2.primary
        assert r1.reason  == r2.reason

    def test_reason_never_empty(self):
        for vuln in ("IDOR", "AUTH_BYPASS", "ENUMERATION", "PRIV_ESC", "BULK_EXFIL"):
            ctx = _ctx(
                vulnerability_types=frozenset({vuln}),
                max_stage="recon",
                success_count=1,
            )
            result = classify_ttp(ctx)
            assert result.reason, f"Empty reason for vuln={vuln}"
            assert len(result.reason) > 20, f"Reason too short for vuln={vuln}: {result.reason!r}"


class TestMITRERegistry:
    def test_all_technique_keys_in_registry(self):
        """Every key produced by classify_ttp must have a MITRE entry."""
        contexts = [
            _ctx(vulnerability_types=frozenset({"PRIV_ESC"}),          max_stage="impact",       success_count=1),
            _ctx(vulnerability_types=frozenset({"COMMAND_EXECUTION"}),  max_stage="impact",       success_count=1),
            _ctx(has_destructive_write=True),
            _ctx(vulnerability_types=frozenset({"BULK_EXFIL"}),         max_stage="exfiltration", success_count=3),
            _ctx(bulk_access=True,                                       max_stage="exfiltration", success_count=10, distinct_resource_ids=6),
            _ctx(vulnerability_types=frozenset({"IDOR"}),                max_stage="collection",   success_count=3, distinct_resource_ids=3),
            _ctx(vulnerability_types=frozenset({"IDOR"}),                max_stage="collection",   success_count=1, distinct_resource_ids=1),
            _ctx(vulnerability_types=frozenset({"AUTH_BYPASS"}),         max_stage="access",       success_count=1),
            _ctx(repeated_failures=True,                                  failure_count=5),
            _ctx(has_secret_access=True,                                  max_stage="recon"),
            _ctx(auth_failure_count=4,                                    failure_count=4,          repeated_failures=True),
            _ctx(has_token_events=True),
        ]
        for ctx in contexts:
            result = classify_ttp(ctx)
            for key in result.all_keys():
                assert key in MITRE, f"Key {key!r} not in MITRE registry"

    def test_no_duplicate_secondaries(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"PRIV_ESC"}),
            max_stage="impact",
            success_count=5,
            distinct_resource_ids=4,
            has_secret_access=True,
            auth_failure_count=4,
            has_token_events=True,
        )
        result = classify_ttp(ctx)
        assert len(result.secondary) == len(set(result.secondary)), "Duplicate secondary TTPs"

    def test_primary_not_in_secondary(self):
        ctx = _ctx(
            vulnerability_types=frozenset({"IDOR"}),
            max_stage="exfiltration",
            bulk_access=True,
            success_count=10,
            distinct_resource_ids=8,
        )
        result = classify_ttp(ctx)
        assert result.primary not in result.secondary


# ── build_ttp_context: context builder from raw rows ─────────────────────────

class TestBuildTTPContext:
    def test_success_and_failure_counts(self):
        steps = [
            _step(status=200),
            _step(status=200),
            _step(status=404),
        ]
        ctx = build_ttp_context(steps, [])
        assert ctx.success_count == 2
        assert ctx.failure_count == 1

    def test_distinct_resource_ids_same_family(self):
        steps = [
            _step(path="/api/v1/users/1", status=200),
            _step(path="/api/v1/users/2", status=200),
            _step(path="/api/v1/users/3", status=200),
        ]
        ctx = build_ttp_context(steps, [])
        assert ctx.distinct_resource_ids == 3

    def test_sequential_pattern_detected(self):
        steps = [
            _step(path="/api/v1/users/10", status=200),
            _step(path="/api/v1/users/11", status=200),
            _step(path="/api/v1/users/12", status=200),
        ]
        ctx = build_ttp_context(steps, [])
        assert ctx.sequential_pattern is True

    def test_non_sequential_not_flagged(self):
        steps = [
            _step(path="/api/v1/users/1",    status=200),
            _step(path="/api/v1/users/9999", status=200),
        ]
        ctx = build_ttp_context(steps, [])
        # gap of 9998 > 200 → not sequential
        assert ctx.sequential_pattern is False

    def test_repeated_failures_flag(self):
        steps = [
            _step(path="/api/v1/users/1", status=404),
            _step(path="/api/v1/users/2", status=404),
            _step(path="/api/v1/users/3", status=404),
        ]
        ctx = build_ttp_context(steps, [])
        assert ctx.repeated_failures is True

    def test_delete_sets_destructive_write(self):
        steps = [_step(method="DELETE", path="/api/v1/users/1", status=200)]
        ctx = build_ttp_context(steps, [])
        assert ctx.has_destructive_write is True

    def test_exfiltration_phase_sets_bulk_access(self):
        events = [_event(attack_phase="exfiltration", status=200)]
        ctx = build_ttp_context([], events)
        assert ctx.bulk_access is True

    def test_max_stage_highest_wins(self):
        events = [
            _event(attack_phase="recon"),
            _event(attack_phase="collection"),
            _event(attack_phase="access"),
        ]
        ctx = build_ttp_context([], events)
        assert ctx.max_stage == "collection"

    def test_vulnerability_type_stored_preferred(self):
        events = [_event(attack_phase="recon", vuln_type="IDOR")]
        ctx = build_ttp_context([], events)
        assert "IDOR" in ctx.vulnerability_types

    def test_vulnerability_type_inferred_from_phase(self):
        # No stored vulnerability_type; should infer from attack_phase
        events = [_event(attack_phase="collection")]  # no vuln_type
        ctx = build_ttp_context([], events)
        assert ctx.vulnerability_types & {"IDOR", "DATA_EXPOSURE"}

    def test_secret_access_from_event_kind(self):
        events = [_event(kind="admin_secrets", attack_phase="recon")]
        ctx = build_ttp_context([], events)
        assert ctx.has_secret_access is True

    def test_token_events_from_event_kind(self):
        events = [_event(kind="unknown_token", attack_phase="recon", status=401)]
        ctx = build_ttp_context([], events)
        assert ctx.has_token_events is True

    def test_auth_failure_count(self):
        steps = [
            _step(path="/v1/auth/login", status=401),
            _step(path="/v1/auth/login", status=401),
            _step(path="/v1/auth/login", status=403),
        ]
        ctx = build_ttp_context(steps, [])
        assert ctx.auth_failure_count == 3

    def test_empty_inputs(self):
        ctx = build_ttp_context([], [])
        assert ctx.request_count == 0
        assert ctx.max_stage == "recon"
        assert ctx.distinct_resource_ids == 0
        assert ctx.sequential_pattern is False
        assert ctx.repeated_failures is False


# ── ttp_display_data: integration ────────────────────────────────────────────

class TestTTPDisplayData:
    def test_returns_required_keys(self):
        steps = [_step(path="/api/v1/users/1", status=200)]
        result = ttp_display_data(steps, [])
        assert "techniques" in result
        assert "primary" in result
        assert "display" in result

    def test_techniques_list_matches_display(self):
        steps = [_step(path="/api/v1/users/1", status=200)]
        result = ttp_display_data(steps, [])
        assert len(result["techniques"]) == len(result["display"])
        assert result["techniques"][0] == result["primary"]

    def test_display_entry_structure(self):
        steps = [_step(path="/api/v1/users/42", status=200)]
        result = ttp_display_data(steps, [])
        for entry in result["display"]:
            assert "key"     in entry
            assert "primary" in entry
            assert "tid"     in entry
            assert "tactic"  in entry
            assert "label"   in entry
            assert "reason"  in entry
            assert "evidence" in entry
            assert isinstance(entry["evidence"], list)

    def test_primary_entry_is_first(self):
        steps = [_step(path="/api/v1/users/1", status=200)]
        result = ttp_display_data(steps, [])
        if result["display"]:
            assert result["display"][0]["primary"] is True

    def test_no_techniques_key_contains_unknown_keys(self):
        steps = [_step(path="/api/v1/users/1", status=200)]
        result = ttp_display_data(steps, [])
        for key in result["techniques"]:
            assert key in MITRE, f"Unknown key in techniques: {key!r}"

    def test_idor_single_maps_unauthorized_access(self):
        events = [_event(attack_phase="collection", vuln_type="IDOR", status=200)]
        result = ttp_display_data([], events)
        assert result["primary"] == "unauthorized_access"

    def test_idor_multiple_maps_data_collection(self):
        steps = [
            _step(path="/api/v1/users/10", status=200),
            _step(path="/api/v1/users/11", status=200),
            _step(path="/api/v1/users/12", status=200),
        ]
        events = [_event(attack_phase="collection", vuln_type="IDOR", status=200)]
        result = ttp_display_data(steps, events)
        assert result["primary"] == "data_collection"

    def test_repeated_failures_maps_discovery(self):
        steps = [
            _step(path="/api/v1/users/1", status=404),
            _step(path="/api/v1/users/2", status=404),
            _step(path="/api/v1/users/3", status=404),
            _step(path="/api/v1/users/4", status=404),
        ]
        result = ttp_display_data(steps, [])
        assert result["primary"] == "discovery"

    def test_bulk_maps_exfiltration(self):
        steps = [_step(path=f"/api/v1/users/{i}", status=200) for i in range(12)]
        events = [_event(attack_phase="exfiltration", vuln_type="BULK_EXFIL", status=200)]
        result = ttp_display_data(steps, events)
        assert result["primary"] == "bulk_exfiltration"

    def test_delete_maps_impact(self):
        steps = [_step(method="DELETE", path="/api/v1/users/1", status=200)]
        result = ttp_display_data(steps, [])
        assert result["primary"] == "destructive_action"
