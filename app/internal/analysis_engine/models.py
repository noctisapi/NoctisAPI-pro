"""Domain models for the attack analysis engine.

All types are immutable frozen dataclasses so the same inputs always
produce the same outputs regardless of execution order.

No I/O.  No DB access.  No side effects.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RequestEvent:
    """Everything the analyzer needs about one HTTP interaction.

    The caller is responsible for pre-fetching the historical context fields
    (interval_ms, recent_statuses, recent_paths, recent_intervals_ms) from
    the database *before* constructing this object.  The analysis engine
    itself never touches the database.

    Fields
    ------
    path                    URL path of the current request (e.g. '/api/v1/users')
    method                  HTTP method, upper-case
    ua                      User-Agent header value (empty string if absent)
    headers                 Full request headers as dict[str, str]
    query_params            URL query parameters as dict[str, str]
    status                  HTTP response status code actually returned
    body_size               Response body size in bytes
    session_request_count   Number of requests *before* this one in the same session
    interval_ms             Milliseconds since this actor's previous request (0 = first)
    recent_statuses         Last N response statuses from this actor, newest first
    recent_paths            Last N request paths from this session, newest first
    recent_intervals_ms     Last N inter-request intervals (ms) for this actor
    """
    path: str
    method: str
    ua: str
    headers: dict
    query_params: dict
    status: int
    body_size: int
    session_request_count: int
    interval_ms: float
    recent_statuses: tuple
    recent_paths: tuple
    recent_intervals_ms: tuple


@dataclass(frozen=True)
class AttackAnalysisResult:
    """Output of AttackAnalyzer.analyze().

    Fields
    ------
    attack_type       "automated" or "targeted"
    confidence_score  0.0 (completely uncertain) → 1.0 (maximally certain)
    signals           dict mapping each signal name to its raw score (0.0–1.0)
    """
    attack_type: str
    confidence_score: float
    signals: dict = field(default_factory=dict)
