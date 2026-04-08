"""AttackAnalyzer — deterministic weighted classifier.

Combines eight heuristic signals into a single classification:
    "automated" | "targeted"

Architecture constraints (enforced here):
  - Pure function behaviour: same RequestEvent → same AttackAnalysisResult.
  - No I/O.  No DB access.  No randomness.  No ML.
  - O(1) per call (all signal functions are O(path_len) or O(1)).

Decision model
--------------
Each signal returns a score in [0, 1]:
  - Automated signals: 1.0 = strongly automated (subtract from final score)
  - Targeted  signals: 1.0 = strongly targeted  (add to final score)

    final_score = 0.5
                + Σ (w_i / W_total) * targeted_signal_i
                − Σ (w_j / W_total) * automated_signal_j

    final_score is clamped to [0.0, 1.0].

    attack_type = "targeted"  if final_score >= THRESHOLD
                  "automated" otherwise

    confidence_score = |final_score − 0.5| × 2   → [0.0, 1.0]
        0.0 = completely undecided; 1.0 = maximum certainty.

Public helpers
--------------
compute_typical_behavior(attack_types)  — pure aggregation over Case history.
"""
from __future__ import annotations

from app.internal.analysis_engine.models import AttackAnalysisResult, RequestEvent
from app.internal.analysis_engine.signals import (
    adaptation_score,
    header_consistency_score,
    multi_step_behavior_score,
    path_entropy_score,
    request_rate_score,
    timing_uniformity_score,
    traversal_logic_score,
    user_agent_score,
)

# ---------------------------------------------------------------------------
# Weight table
# ---------------------------------------------------------------------------
# Weights are relative; they are normalised before use so their absolute
# magnitude does not matter — only the ratios between them.

_SIGNAL_WEIGHTS: dict[str, float] = {
    # automated signals
    "request_rate":        0.20,
    "path_entropy":        0.15,
    "header_consistency":  0.10,
    "user_agent":          0.15,
    "timing_uniformity":   0.10,
    # targeted signals
    "traversal_logic":     0.15,
    "multi_step_behavior": 0.20,
    "adaptation":          0.15,
}

_AUTOMATED_SIGNALS = frozenset({
    "request_rate", "path_entropy", "header_consistency",
    "user_agent", "timing_uniformity",
})

_TARGETED_SIGNALS = frozenset({
    "traversal_logic", "multi_step_behavior", "adaptation",
})

# final_score >= _THRESHOLD → "targeted"
_THRESHOLD: float = 0.5

# Total weight (constant; used for normalisation)
_TOTAL_WEIGHT: float = sum(_SIGNAL_WEIGHTS.values())

# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

_SIGNAL_FNS = {
    "request_rate":        request_rate_score,
    "path_entropy":        path_entropy_score,
    "header_consistency":  header_consistency_score,
    "user_agent":          user_agent_score,
    "timing_uniformity":   timing_uniformity_score,
    "traversal_logic":     traversal_logic_score,
    "multi_step_behavior": multi_step_behavior_score,
    "adaptation":          adaptation_score,
}


class AttackAnalyzer:
    """Classify one RequestEvent as 'automated' or 'targeted'.

    Stateless: instantiation is cheap; create a new instance per call or
    share one instance — either is safe.
    """

    def analyze(self, event: RequestEvent) -> AttackAnalysisResult:
        """Classify *event* and return a fully populated AttackAnalysisResult.

        Same input always produces the same output (deterministic, no I/O).
        """
        signals: dict[str, float] = {
            name: fn(event) for name, fn in _SIGNAL_FNS.items()
        }

        delta = 0.0
        for name, raw_score in signals.items():
            w = _SIGNAL_WEIGHTS[name] / _TOTAL_WEIGHT
            if name in _AUTOMATED_SIGNALS:
                delta -= w * raw_score
            else:  # targeted
                delta += w * raw_score

        final_score = max(0.0, min(1.0, 0.5 + delta))
        attack_type = "targeted" if final_score >= _THRESHOLD else "automated"
        confidence  = round(abs(final_score - 0.5) * 2.0, 4)

        return AttackAnalysisResult(
            attack_type=attack_type,
            confidence_score=confidence,
            signals={k: round(v, 4) for k, v in signals.items()},
        )


# ---------------------------------------------------------------------------
# Pure aggregation helper (used by Actor enrichment)
# ---------------------------------------------------------------------------

def compute_typical_behavior(attack_types: list[str]) -> str:
    """Majority-vote classification over a list of Case attack_type values.

    Returns "automated", "targeted", or "mixed" (tie or empty input).
    No I/O.  No DB access.
    """
    counts: dict[str, int] = {"automated": 0, "targeted": 0}
    for t in attack_types:
        if t in counts:
            counts[t] += 1

    auto  = counts["automated"]
    tgt   = counts["targeted"]

    if tgt > auto:
        return "targeted"
    if auto > tgt:
        return "automated"
    return "mixed"
