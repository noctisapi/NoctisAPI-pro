"""Stage classification types.

Stage represents the phase of an attack, not the actor's cumulative threat level.
It is determined per-request from vulnerability type + behaviour signals.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Stage(Enum):
    """Attack phase — the single canonical Stage vocabulary.

    Values must never be created outside this enum.
    Priority (highest → lowest): IMPACT > EXFILTRATION > COLLECTION > ACCESS > RECON
    """
    RECON        = "recon"
    ACCESS       = "access"
    COLLECTION   = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT       = "impact"


@dataclass(frozen=True)
class StageResult:
    """Output of classify_stage — stage + human-readable explanation."""
    stage: Stage
    reason: str


# ── Input contexts ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RequestContext:
    """Everything knowable about the current HTTP request/response."""
    endpoint_id: str        # catalog endpoint id, empty string if not mapped
    method: str             # HTTP method, upper-case
    path: str               # URL path (with resolved params, e.g. /users/42)
    query_params: dict
    body: dict
    headers: dict
    response_status: int    # HTTP response status code actually returned
    response_size: int      # response body size in bytes


@dataclass(frozen=True)
class DetectionContext:
    """Vulnerability and signal data for the current request."""
    vulnerability_type: Optional[str] = None  # canonical vuln type from EndpointDefinition
    ttp: Optional[str] = None                 # MITRE ATT&CK reference, e.g. "T1110"
    flags: dict = field(default_factory=dict) # e.g. {"bulk": True, "suspicious_pattern": True}


@dataclass(frozen=True)
class CaseContext:
    """Behavioural context across the current session/case."""
    previous_requests_in_session: int = 0    # total requests before this one in session
    unique_resource_ids_accessed: int = 1    # distinct parameterised IDs seen in session
    time_window_seconds: int = 300
