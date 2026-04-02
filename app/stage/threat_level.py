"""Numeric threat level (0–8) derived from a cumulative actor score.

This is a DIFFERENT concept from Stage (attack phase).
  - Stage    = what type of attack is happening right now (per-request)
  - Threat level = how dangerous this actor is overall (cumulative score)

This module is the single canonical implementation.
All other copies in honeypot_public.py, campaigns_pro.py, panel_mvp.py,
and alert_dispatcher.py must be replaced with imports from here.
"""
from __future__ import annotations

STAGE_LABELS: dict[int, str] = {
    0: "0–Idle",
    1: "1–Curious",
    2: "2–Exploring",
    3: "3–Probing",
    4: "4–Targeting",
    5: "5–Aggressive",
    6: "6–Exploiting",
    7: "7–Persistent",
    8: "8–Critical",
}


def stage_from_score(score: int) -> int:
    """Map a cumulative actor score to a threat level (0–8)."""
    if score < 10:  return 0
    if score < 20:  return 1
    if score < 32:  return 2
    if score < 48:  return 3
    if score < 68:  return 4
    if score < 92:  return 5
    if score < 120: return 6
    if score < 155: return 7
    return 8


def stage_label(score: int) -> str:
    """Human-readable threat level label for a given score."""
    return STAGE_LABELS.get(stage_from_score(score), "?")
