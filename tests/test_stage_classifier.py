"""Unit tests for the Stage classifier.

Validates that classify_stage() is deterministic, depends only on its explicit
inputs, and produces the correct Stage for each attack pattern.

Test matrix:
  IDOR single request             → COLLECTION
  IDOR + high session count       → EXFILTRATION
  IDOR + bulk response            → EXFILTRATION
  ENUMERATION                     → RECON
  AUTH_BYPASS + success (200)     → ACCESS
  AUTH_BYPASS + failure (401)     → RECON
  DELETE + success (200)          → IMPACT
  COMMAND_EXECUTION               → IMPACT
  PRIV_ESC                        → IMPACT
  BULK_EXFIL                      → EXFILTRATION
  DATA_EXPOSURE + success         → COLLECTION
  Unknown endpoint (no vuln type) → RECON
  Non-200 with IDOR               → RECON (not collection; access denied)
"""
import pytest

from app.stage.types import CaseContext, DetectionContext, RequestContext, Stage
from app.stage.classifier import (
    _BULK_SESSION_REQS,
    _BULK_SIZE_BYTES,
    classify_stage,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _req(
    *,
    method: str = "GET",
    path: str = "/api/v1/test",
    status: int = 200,
    size: int = 512,
) -> RequestContext:
    return RequestContext(
        endpoint_id="test_endpoint",
        method=method,
        path=path,
        query_params={},
        body={},
        headers={},
        response_status=status,
        response_size=size,
    )


def _det(vuln: str | None = None, flags: dict | None = None) -> DetectionContext:
    return DetectionContext(vulnerability_type=vuln, flags=flags or {})


def _case(prev: int = 0, unique_ids: int = 1) -> CaseContext:
    return CaseContext(
        previous_requests_in_session=prev,
        unique_resource_ids_accessed=unique_ids,
    )


# ── COLLECTION ────────────────────────────────────────────────────────────────

def test_idor_single_request_is_collection():
    result = classify_stage(_req(status=200), _det("IDOR"), _case(prev=0))
    assert result.stage is Stage.COLLECTION
    assert "IDOR" in result.reason


def test_idor_multiple_ids_is_collection():
    """Multiple IDs accessed but below bulk threshold → still COLLECTION."""
    result = classify_stage(
        _req(status=200),
        _det("IDOR"),
        _case(prev=5, unique_ids=4),
    )
    assert result.stage is Stage.COLLECTION
    assert "4" in result.reason or "IDOR" in result.reason


def test_data_exposure_success_is_collection():
    result = classify_stage(_req(status=200), _det("DATA_EXPOSURE"), _case())
    assert result.stage is Stage.COLLECTION


# ── EXFILTRATION ──────────────────────────────────────────────────────────────

def test_idor_high_session_count_is_exfiltration():
    """Session with many IDOR requests crosses scraping threshold."""
    result = classify_stage(
        _req(status=200),
        _det("IDOR"),
        _case(prev=_BULK_SESSION_REQS),
    )
    assert result.stage is Stage.EXFILTRATION
    assert str(_BULK_SESSION_REQS) in result.reason or "scraping" in result.reason


def test_idor_bulk_response_size_is_exfiltration():
    """Large response body signals bulk exfiltration."""
    result = classify_stage(
        _req(status=200, size=_BULK_SIZE_BYTES + 1),
        _det("IDOR"),
        _case(),
    )
    assert result.stage is Stage.EXFILTRATION


def test_idor_bulk_flag_is_exfiltration():
    """Explicit bulk flag overrides normal collection."""
    result = classify_stage(
        _req(status=200),
        _det("IDOR", flags={"bulk": True}),
        _case(),
    )
    assert result.stage is Stage.EXFILTRATION
    assert "bulk" in result.reason


def test_bulk_exfil_vuln_type_is_exfiltration():
    result = classify_stage(_req(status=200), _det("BULK_EXFIL"), _case())
    assert result.stage is Stage.EXFILTRATION


# ── ACCESS ────────────────────────────────────────────────────────────────────

def test_auth_bypass_success_is_access():
    result = classify_stage(_req(status=200), _det("AUTH_BYPASS"), _case())
    assert result.stage is Stage.ACCESS
    assert "AUTH_BYPASS" in result.reason


def test_weak_auth_success_is_access():
    result = classify_stage(_req(status=200), _det("WEAK_AUTH"), _case())
    assert result.stage is Stage.ACCESS


def test_auth_bypass_failure_is_recon():
    """A failed auth attempt (401) is reconnaissance, not access."""
    result = classify_stage(_req(status=401), _det("AUTH_BYPASS"), _case())
    assert result.stage is Stage.RECON


# ── RECON ─────────────────────────────────────────────────────────────────────

def test_enumeration_is_recon():
    result = classify_stage(_req(status=200), _det("ENUMERATION"), _case())
    assert result.stage is Stage.RECON
    assert "ENUMERATION" in result.reason


def test_no_vuln_type_is_recon():
    result = classify_stage(_req(status=200), _det(None), _case())
    assert result.stage is Stage.RECON


def test_probe_returning_404_is_recon():
    result = classify_stage(_req(status=404), _det(None), _case())
    assert result.stage is Stage.RECON
    assert "404" in result.reason


def test_idor_denied_is_recon():
    """IDOR attempt that returns 403 is still RECON — access was not granted."""
    result = classify_stage(_req(status=403), _det("IDOR"), _case())
    assert result.stage is Stage.RECON


# ── IMPACT ────────────────────────────────────────────────────────────────────

def test_delete_success_is_impact():
    result = classify_stage(_req(method="DELETE", status=204), _det(None), _case())
    assert result.stage is Stage.IMPACT
    assert "DELETE" in result.reason


def test_command_execution_is_impact():
    result = classify_stage(_req(status=200), _det("COMMAND_EXECUTION"), _case())
    assert result.stage is Stage.IMPACT


def test_priv_esc_is_impact():
    result = classify_stage(_req(status=200), _det("PRIV_ESC"), _case())
    assert result.stage is Stage.IMPACT


def test_destructive_action_is_impact():
    result = classify_stage(_req(status=200), _det("DESTRUCTIVE_ACTION"), _case())
    assert result.stage is Stage.IMPACT


# ── Priority resolution ───────────────────────────────────────────────────────

def test_impact_beats_collection():
    """PRIV_ESC has higher priority than IDOR even if both signals are present."""
    result = classify_stage(
        _req(method="GET", status=200),
        _det("PRIV_ESC", flags={}),
        _case(),
    )
    assert result.stage is Stage.IMPACT


def test_exfiltration_beats_collection():
    """bulk flag elevates IDOR from COLLECTION to EXFILTRATION."""
    result = classify_stage(
        _req(status=200),
        _det("IDOR", flags={"bulk": True}),
        _case(prev=0),
    )
    assert result.stage is Stage.EXFILTRATION


# ── Determinism ───────────────────────────────────────────────────────────────

def test_same_inputs_same_result():
    """Identical inputs must always produce the same Stage."""
    req = _req(status=200)
    det = _det("IDOR")
    case = _case(prev=3)
    results = [classify_stage(req, det, case) for _ in range(10)]
    stages = {r.stage for r in results}
    reasons = {r.reason for r in results}
    assert len(stages) == 1, "Stage must be deterministic"
    assert len(reasons) == 1, "Reason must be deterministic"


# ── StageResult contract ──────────────────────────────────────────────────────

def test_result_has_non_empty_reason():
    result = classify_stage(_req(), _det("IDOR"), _case())
    assert isinstance(result.reason, str)
    assert len(result.reason) > 0


def test_stage_values_are_canonical():
    """All Stage enum values are the ones specified in the canonical set."""
    assert {s.value for s in Stage} == {
        "recon", "access", "collection", "exfiltration", "impact"
    }
