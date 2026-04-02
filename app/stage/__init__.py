"""app.stage — attack phase classification, TTP mapping, and threat level.

Public interface:
    Stage, StageResult, RequestContext, DetectionContext, CaseContext
        → types used to build inputs for classify_stage

    classify_stage(req, det, case) -> StageResult
        → per-request attack phase classifier; never raises

    TTPContext, TTPResult, MITRE
        → types and registry for session-level TTP classification

    build_ttp_context(steps, events) -> TTPContext
        → aggregate behavioral signals from session data

    classify_ttp(ctx) -> TTPResult
        → the single canonical TTP classifier; never raises

    ttp_display_data(steps, events) -> dict
        → full display structure for MITRE ATT&CK template section

    stage_from_score(score) -> int
        → numeric threat level (0–8) from cumulative actor score

    stage_label(score) -> str
        → human-readable threat level label ("4–Targeting")

    STAGE_LABELS
        → dict[int, str] mapping threat level to label
"""
from app.stage.types import (
    CaseContext,
    DetectionContext,
    RequestContext,
    Stage,
    StageResult,
)
from app.stage.classifier import classify_stage
from app.stage.threat_level import STAGE_LABELS, stage_from_score, stage_label
from app.stage.ttp import (
    MITRE,
    TTPContext,
    TTPResult,
    build_ttp_context,
    classify_ttp,
    ttp_display_data,
)

__all__ = [
    "Stage",
    "StageResult",
    "RequestContext",
    "DetectionContext",
    "CaseContext",
    "classify_stage",
    "stage_from_score",
    "stage_label",
    "STAGE_LABELS",
    "MITRE",
    "TTPContext",
    "TTPResult",
    "build_ttp_context",
    "classify_ttp",
    "ttp_display_data",
]
