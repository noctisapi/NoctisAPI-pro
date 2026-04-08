"""Heuristic signal functions for attack classification.

Each function accepts a RequestEvent and returns a normalized float in [0, 1].

Automated signals (high score = more automated):
    request_rate_score        — high request frequency
    path_entropy_score        — random / high-entropy path strings
    header_consistency_score  — minimal / tool-like header set
    user_agent_score          — known scanner tools or missing UA
    timing_uniformity_score   — constant inter-request intervals

Targeted signals (high score = more targeted):
    traversal_logic_score     — logical endpoint progression
    multi_step_behavior_score — stateful multi-request interaction
    adaptation_score          — strategy change after error responses

All functions are pure: same input → same output.
No I/O.  No randomness.  No DB access.
"""
from __future__ import annotations

import math
import re

from app.internal.analysis_engine.models import RequestEvent

# ---------------------------------------------------------------------------
# Automated signal: request_rate_score
# ---------------------------------------------------------------------------

def request_rate_score(event: RequestEvent) -> float:
    """High request frequency suggests automated tooling.

    Uses interval_ms (time since previous request from this actor).
    The shorter the interval, the higher the score.
    0 (first-ever request or no history) → 0.0 (no information).
    """
    ms = event.interval_ms
    if ms <= 0:
        return 0.0
    if ms < 100:
        return 1.0
    if ms < 500:
        return 0.85
    if ms < 2_000:
        return 0.55
    if ms < 10_000:
        return 0.25
    if ms < 60_000:
        return 0.05
    return 0.0


# ---------------------------------------------------------------------------
# Automated signal: path_entropy_score
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_HEX32_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits over the character distribution of s."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def path_entropy_score(event: RequestEvent) -> float:
    """High-entropy or random-looking paths suggest automated scanning.

    Combines Shannon entropy of the path string with pattern detection
    for UUID and long hex sequences (common in scanner-generated URLs).
    """
    path = event.path or "/"

    entropy = _shannon_entropy(path.lower())
    # Typical short API paths score ~2.5–3.2 bits; random GUIDs push toward 4.0+
    # Clamp and scale: 0 bits → 0.0, 4.5+ bits → 1.0
    entropy_score = min(1.0, max(0.0, (entropy - 2.0) / 2.5))

    # Bonus: UUID or long-hex segment present → strong scanner indicator
    bonus = 0.0
    if _UUID_RE.search(path):
        bonus = 0.25
    elif _HEX32_RE.search(path):
        bonus = 0.15

    return min(1.0, entropy_score + bonus)


# ---------------------------------------------------------------------------
# Automated signal: header_consistency_score
# ---------------------------------------------------------------------------

# Headers that real browsers always include; their absence is suspicious.
_BROWSER_HEADERS = ("accept", "accept-language", "accept-encoding")


def header_consistency_score(event: RequestEvent) -> float:
    """Minimal or tool-like header set suggests automated tooling.

    Real browsers always send Accept, Accept-Language, and Accept-Encoding.
    Most automation frameworks omit some or all of these.
    Very few total headers (≤ 2) is an additional indicator.
    """
    lower_headers = {k.lower() for k in event.headers}
    missing = sum(1 for h in _BROWSER_HEADERS if h not in lower_headers)

    score = missing * 0.28  # each missing header contributes ~0.28

    if len(lower_headers) <= 2:
        score += 0.16  # extremely minimal header set

    return min(1.0, score)


# ---------------------------------------------------------------------------
# Automated signal: user_agent_score
# ---------------------------------------------------------------------------

# Sub-strings found in known scanner / automation tool UAs (all lower-case).
_TOOL_UA_FRAGMENTS = frozenset({
    "curl", "wget", "libwww-perl", "python-requests", "python-httpx",
    "python/", "go-http-client", "java/", "okhttp", "ruby",
    "nikto", "masscan", "nmap", "nuclei", "dirbuster", "gobuster",
    "wfuzz", "sqlmap", "hydra", "burpsuite", "zaproxy",
    "acunetix", "nessus", "openvas", "w3af",
    "scanner", "crawler", "spider", "bot/",
    "postman", "insomnia", "httpie", "httpclient",
    "axios", "node-fetch", "got/", "undici",
})


def user_agent_score(event: RequestEvent) -> float:
    """Known scanner tools or absent User-Agent header indicates automation."""
    ua = (event.ua or "").strip().lower()

    if not ua:
        return 1.0  # missing UA is the strongest single automated signal

    for fragment in _TOOL_UA_FRAGMENTS:
        if fragment in ua:
            return 0.9  # recognized tool

    if len(ua) < 12:
        return 0.7  # unusually short UA

    if "mozilla" not in ua:
        # Real browsers always include "Mozilla/5.0"; absence suggests a script
        return 0.35

    return 0.0


# ---------------------------------------------------------------------------
# Automated signal: timing_uniformity_score
# ---------------------------------------------------------------------------

def timing_uniformity_score(event: RequestEvent) -> float:
    """Constant inter-request intervals suggest scripted / automated behaviour.

    Uses the coefficient of variation (CV = σ/μ) of recent_intervals_ms.
    Low CV means uniform timing; high CV means irregular (human-like) timing.
    Requires at least 2 data points; returns 0.0 when insufficient history.
    """
    intervals = event.recent_intervals_ms
    if len(intervals) < 2:
        return 0.0

    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return 1.0  # zero-delay repeats → fully automated

    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    cv = math.sqrt(variance) / mean  # coefficient of variation

    # Low CV = uniform timing = automated
    if cv < 0.05:
        return 1.0
    if cv < 0.15:
        return 0.8
    if cv < 0.30:
        return 0.5
    if cv < 0.60:
        return 0.2
    return 0.0


# ---------------------------------------------------------------------------
# Targeted signal: traversal_logic_score
# ---------------------------------------------------------------------------

def traversal_logic_score(event: RequestEvent) -> float:
    """Logical endpoint progression indicates a targeted, goal-directed attacker.

    Checks three sub-signals:
    1. Shared path prefix — the actor is navigating within the same API area.
    2. Gradually increasing path depth — broad-to-specific exploration pattern.
    3. Moderate path revisitation — targeted actors return to the same resources.
    """
    paths = event.recent_paths
    if len(paths) < 2:
        return 0.0

    score = 0.0

    # 1. Common prefix: most recent two paths share ≥ 2 segments.
    seg_curr = (event.path or "/").split("/")
    seg_prev = paths[0].split("/")
    common_depth = 0
    for a, b in zip(seg_curr, seg_prev):
        if a == b:
            common_depth += 1
        else:
            break
    if common_depth >= 3:
        score += 0.4
    elif common_depth >= 2:
        score += 0.2

    # 2. Increasing path depth over session history (exploration pattern).
    window = list(paths[:6])
    if len(window) >= 3:
        depths = [len(p.split("/")) for p in window]
        rising = sum(1 for a, b in zip(depths, depths[1:]) if b >= a)
        if rising / (len(depths) - 1) >= 0.6:
            score += 0.3

    # 3. Some path revisitation (targeted actors probe the same resources).
    sample = list(paths[:10])
    if sample:
        unique_ratio = len(set(sample)) / len(sample)
        if unique_ratio < 0.6:   # >40 % revisits
            score += 0.3
        elif unique_ratio < 0.85:
            score += 0.1

    return min(1.0, score)


# ---------------------------------------------------------------------------
# Targeted signal: multi_step_behavior_score
# ---------------------------------------------------------------------------

def multi_step_behavior_score(event: RequestEvent) -> float:
    """Stateful multi-request interactions indicate a targeted attacker.

    Sub-signals:
    1. High session request count — the actor is sustaining a focused session.
    2. Mutating HTTP method (POST/PUT/PATCH/DELETE) — going beyond passive recon.
    3. Authorization header present — authenticated session exploration.
    """
    score = 0.0

    count = event.session_request_count
    if count >= 20:
        score += 0.5
    elif count >= 10:
        score += 0.38
    elif count >= 5:
        score += 0.25
    elif count >= 2:
        score += 0.10

    if event.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        score += 0.25

    lower_h = {k.lower() for k in event.headers}
    if "authorization" in lower_h:
        score += 0.25

    return min(1.0, score)


# ---------------------------------------------------------------------------
# Targeted signal: adaptation_score
# ---------------------------------------------------------------------------

_ERROR_STATUSES = frozenset({400, 401, 403, 404, 405, 429, 500, 502, 503})


def adaptation_score(event: RequestEvent) -> float:
    """Changing strategy in response to server responses indicates a targeted attacker.

    Sub-signals:
    1. Path change after an error response — pivoting when blocked.
    2. Mix of successes and failures — interactive probing, not blind scanning.
    3. Mutating method after a successful recon request — escalating from GET.
    """
    score = 0.0

    recent_st = event.recent_statuses
    recent_p  = event.recent_paths

    # 1. Previous request was an error and the current path differs.
    if recent_st and recent_p:
        prev_status = recent_st[0]
        prev_path   = recent_p[0]
        if prev_status in _ERROR_STATUSES and prev_path != event.path:
            score += 0.45

    # 2. Mix of 2xx successes and 4xx/5xx failures in recent history.
    if len(recent_st) >= 3:
        successes = sum(1 for s in recent_st if 200 <= s < 300)
        failures  = sum(1 for s in recent_st if s >= 400)
        if successes > 0 and failures > 0:
            score += 0.30

    # 3. Current request uses a mutating method and there is prior session history.
    if event.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        if event.session_request_count >= 2:
            score += 0.25

    return min(1.0, score)
