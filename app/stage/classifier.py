"""Stage classifier — the single source of truth for attack phase classification.

ALL stage assignments must go through classify_stage().
No other code should derive or assign Stage values.

Priority order (highest wins when multiple rules fire):
    IMPACT > EXFILTRATION > COLLECTION > ACCESS > RECON
"""
from __future__ import annotations

from app.stage.types import (
    CaseContext,
    DetectionContext,
    RequestContext,
    Stage,
    StageResult,
)

# ── Canonical vulnerability type sets ────────────────────────────────────────
# These map to Stage via the classifier rules below.
# Keep in sync with EndpointDefinition.vulnerability_type values.

_IMPACT_VULNS = frozenset({
    "PRIV_ESC",
    "DESTRUCTIVE_ACTION",
    "COMMAND_EXECUTION",
})

_EXFIL_VULNS = frozenset({
    "BULK_EXFIL",
})

_COLLECTION_VULNS = frozenset({
    "IDOR",
    "DATA_EXPOSURE",
})

_ACCESS_VULNS = frozenset({
    "AUTH_BYPASS",
    "WEAK_AUTH",
})

_RECON_VULNS = frozenset({
    "ENUMERATION",
})

# ── Thresholds ────────────────────────────────────────────────────────────────

_BULK_SIZE_BYTES    = 51_200   # 50 KB response → exfiltration signal
_BULK_SESSION_REQS  = 15       # requests in session before collection becomes exfil

# ── Internal predicates ───────────────────────────────────────────────────────

def _is_success(status: int) -> bool:
    return status in (200, 201, 202, 204)


def _is_bulk(req: RequestContext, det: DetectionContext) -> bool:
    return bool(det.flags.get("bulk")) or req.response_size > _BULK_SIZE_BYTES


# ── IMPACT ────────────────────────────────────────────────────────────────────

def _check_impact(req: RequestContext, det: DetectionContext) -> StageResult | None:
    vuln = (det.vulnerability_type or "").upper()

    if vuln in _IMPACT_VULNS:
        return StageResult(
            Stage.IMPACT,
            f"{vuln} on {req.path} → privilege escalation or destructive action",
        )

    if req.method.upper() == "DELETE" and _is_success(req.response_status):
        return StageResult(
            Stage.IMPACT,
            f"Successful DELETE {req.path} (status {req.response_status}) → destructive action",
        )

    return None


# ── EXFILTRATION ──────────────────────────────────────────────────────────────

def _check_exfiltration(
    req: RequestContext, det: DetectionContext, case: CaseContext
) -> StageResult | None:
    vuln = (det.vulnerability_type or "").upper()

    if vuln in _EXFIL_VULNS:
        return StageResult(
            Stage.EXFILTRATION,
            f"{vuln} on {req.path} → bulk data exfiltration",
        )

    if _is_bulk(req, det) and vuln in _COLLECTION_VULNS and _is_success(req.response_status):
        detail = (
            "bulk flag set"
            if det.flags.get("bulk")
            else f"response_size={req.response_size} bytes"
        )
        return StageResult(
            Stage.EXFILTRATION,
            f"Bulk {vuln} access on {req.path} ({detail}) → exfiltration",
        )

    if (
        case.previous_requests_in_session >= _BULK_SESSION_REQS
        and vuln in _COLLECTION_VULNS
        and _is_success(req.response_status)
    ):
        return StageResult(
            Stage.EXFILTRATION,
            f"High-volume {vuln} scraping: {case.previous_requests_in_session} prior requests "
            f"in session on {req.path} → exfiltration pattern",
        )

    return None


# ── COLLECTION ────────────────────────────────────────────────────────────────

def _check_collection(
    req: RequestContext, det: DetectionContext, case: CaseContext
) -> StageResult | None:
    vuln = (det.vulnerability_type or "").upper()

    if vuln in _COLLECTION_VULNS and _is_success(req.response_status):
        if case.unique_resource_ids_accessed > 1:
            return StageResult(
                Stage.COLLECTION,
                f"{vuln} with sequential access to {case.unique_resource_ids_accessed} distinct "
                f"resource IDs on {req.path} → collection",
            )
        return StageResult(
            Stage.COLLECTION,
            f"{vuln} on {req.path} (status {req.response_status}) → data collection",
        )

    return None


# ── ACCESS ────────────────────────────────────────────────────────────────────

def _check_access(
    req: RequestContext, det: DetectionContext, case: CaseContext
) -> StageResult | None:
    vuln = (det.vulnerability_type or "").upper()

    if vuln in _ACCESS_VULNS and _is_success(req.response_status):
        return StageResult(
            Stage.ACCESS,
            f"Successful {vuln} on {req.path} (status {req.response_status}) → initial access",
        )

    return None


# ── Public classifier ─────────────────────────────────────────────────────────

def classify_stage(
    req: RequestContext,
    det: DetectionContext,
    case: CaseContext,
) -> StageResult:
    """Classify the attack phase for a single request.

    Rules are evaluated in strict priority order.  The first matching rule wins.
    Inputs must be fully constructed before calling — no implicit state is read.

    Returns a StageResult with the determined Stage and an explanation string.
    Never raises; falls back to RECON on unexpected input.
    """
    try:
        vuln = (det.vulnerability_type or "").upper()

        # Priority 1 — IMPACT
        result = _check_impact(req, det)
        if result:
            return result

        # Priority 2 — EXFILTRATION
        result = _check_exfiltration(req, det, case)
        if result:
            return result

        # Priority 3 — COLLECTION
        result = _check_collection(req, det, case)
        if result:
            return result

        # Priority 4 — ACCESS
        result = _check_access(req, det, case)
        if result:
            return result

        # Priority 5 — RECON (default)
        if vuln in _RECON_VULNS:
            return StageResult(Stage.RECON, f"ENUMERATION activity on {req.path}")

        if not _is_success(req.response_status):
            return StageResult(
                Stage.RECON,
                f"Probe on {req.path} returned {req.response_status} → reconnaissance",
            )

        return StageResult(Stage.RECON, f"Discovery/probe on {req.path}")

    except Exception as exc:  # pragma: no cover
        return StageResult(Stage.RECON, f"classifier error ({exc}) → fallback to RECON")
