"""Attack classification analysis engine.

Public API:
    AttackAnalyzer      — classify a single RequestEvent
    AttackAnalysisResult — structured result of classification
    RequestEvent        — pre-populated event context (no I/O inside)
    compute_typical_behavior — pure aggregation over historical attack_types
"""
from app.internal.analysis_engine.models import AttackAnalysisResult, RequestEvent
from app.internal.analysis_engine.analyzer import AttackAnalyzer, compute_typical_behavior

__all__ = [
    "AttackAnalyzer",
    "AttackAnalysisResult",
    "RequestEvent",
    "compute_typical_behavior",
]
