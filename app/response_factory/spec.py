"""ResponseSpec — the output contract of ResponseFactory.

This dataclass is the single value that travels from ResponseFactory
to the HTTP layer and to InteractionContextBuilder.

Design rules:
  - Frozen dataclass: immutable after construction.
  - No FastAPI/Starlette dependency: plain Python types only.
  - body is always a plain Python value (dict/list/str/None) —
    serialisation to bytes happens at the HTTP layer.
  - triggered_flaws carries the flaw_profile_ids that actually fired,
    so InteractionContextBuilder does not need to re-detect them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class ResponseSpec:
    """Fully resolved response specification produced by ResponseFactory.

    Fields:
      endpoint_id       Stable catalog id (for correlation/logging).
      status_code       HTTP status code to send (100–599).
      headers           HTTP headers to set (merged on top of profile defaults).
      body              Response body (dict | list | str | None).
                        None → empty body (e.g. 204 No Content).
      content_type      MIME type, e.g. "application/json" or "text/plain".
      latency_ms        Recommended artificial delay before sending the response.
                        0 = no delay. The bridge injects this delay.
      triggered_flaws   flaw_profile_ids that fired during generation.
                        Used by InteractionContextBuilder.
      outcome_hints     Optional free-form dict for extra metadata passed
                        to safe_extra_json_fragment via extra_hints.
    """
    endpoint_id: str
    status_code: int
    headers: dict[str, str]
    body: Any
    content_type: str
    latency_ms: int
    triggered_flaws: tuple[str, ...]
    outcome_hints: dict[str, Any] = field(default_factory=dict)

    # ── Convenience ───────────────────────────────────────────────────────────

    @property
    def has_json_body(self) -> bool:
        return "json" in self.content_type and self.body is not None

    @property
    def has_text_body(self) -> bool:
        return "text/plain" in self.content_type and self.body is not None

    @property
    def response_bytes(self) -> int:
        """Rough byte estimate for InteractionContext."""
        if self.body is None:
            return 0
        if isinstance(self.body, (dict, list)):
            import json
            try:
                return len(json.dumps(self.body).encode())
            except Exception:
                return 0
        return len(str(self.body).encode())
