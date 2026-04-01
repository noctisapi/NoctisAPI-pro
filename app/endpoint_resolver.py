"""EndpointResolver — semantic resolution of HTTP requests to EffectiveEndpoints.

PURPOSE:
  Given an HTTP (method, path), return the EffectiveEndpoint from the catalog
  that best describes what this request *means* — without touching the existing
  routing, middleware, or scoring logic.

ALGORITHM:
  1. Exact (method, path) match against EffectiveRuntimeConfig.endpoints.
     Fast O(n) scan; catalog is small (<200 entries).
  2. Pattern match: compare request path against endpoint path_patterns that
     contain {param} placeholders.  e.g.:
       pattern "/api/v1/orders/{order_id}" matches request "/api/v1/orders/123"
  3. Highest specificity wins when multiple patterns match.
     Specificity = count of literal segments (non-{param}).

RETURNS:
  Optional[EffectiveEndpoint]
  None when no catalog entry matches (scanner probes, unknown paths, etc.).
  Never raises.

PUBLIC API:
  EndpointResolver(provider)         — class, inject provider for testing
  resolve_effective_endpoint(m, p)   — module-level shortcut (uses global provider)
  _pattern_matches(pattern, path)    — exported for LegacyConfigAdapter
  _specificity_score(pattern)        — exported for LegacyConfigAdapter

NOTE:
  This module does NOT replace the existing api_modular.resolve_request_policy().
  Both run independently:
    - api_modular  → controls response_mode, mutation, rules (existing)
    - EndpointResolver → provides semantic endpoint_id, operation_type, etc. (new)
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Optional

from app.runtime.models import EffectiveEndpoint, EffectiveRuntimeConfig

if TYPE_CHECKING:
    from app.runtime_provider import RuntimeConfigProvider

logger = logging.getLogger(__name__)

# ── Path pattern matching ─────────────────────────────────────────────────────

# Match {anything} placeholders in Starlette/FastAPI path patterns.
_PARAM_RE = re.compile(r"\{[^}]+\}")


def _pattern_matches(pattern: str, path: str) -> bool:
    """Return True if `path` matches the `pattern` (which may contain {params}).

    Rules:
      - Segment count must match exactly (no partial prefix matching).
      - Literal segments must match exactly.
      - {param} segments match any single non-empty path segment.
      - Trailing slashes are normalised away before comparison.

    Examples:
      _pattern_matches("/api/v1/orders/{id}", "/api/v1/orders/123")   → True
      _pattern_matches("/api/v1/orders/{id}", "/api/v1/orders/123/x") → False
      _pattern_matches("/api/v1/orders",      "/api/v1/orders")       → True
      _pattern_matches("/api/v1/orders",      "/api/v1/orders/123")   → False
      _pattern_matches("/.env",              "/.env")                 → True
    """
    pattern_parts = pattern.rstrip("/").split("/")
    path_parts = path.rstrip("/").split("/")

    if len(pattern_parts) != len(path_parts):
        return False

    for pp, rp in zip(pattern_parts, path_parts):
        is_param = pp.startswith("{") and pp.endswith("}")
        if not is_param and pp != rp:
            return False

    return True


def _specificity_score(pattern: str) -> int:
    """Higher score = more specific (more literal segments).

    Used to pick the best match when multiple patterns match the same path.
    e.g. "/api/v1/orders/{id}" scores 3 (three literal segments).
    """
    return sum(
        0 if (part.startswith("{") and part.endswith("}")) else 1
        for part in pattern.split("/")
    )


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert a {param} path pattern to a compiled regex.

    Only used internally; prefer _pattern_matches() for simple cases.
    """
    escaped = re.escape(pattern.rstrip("/"))
    regex = _PARAM_RE.sub(r"([^/]+)", escaped)
    return re.compile(f"^{regex}$")


# ── EndpointResolver ──────────────────────────────────────────────────────────

class EndpointResolver:
    """Resolves (method, path) → EffectiveEndpoint using the catalog.

    Designed for injection: pass a RuntimeConfigProvider to control what
    catalog version is used. This makes the resolver fully testable without
    global state.

    Usage:
        resolver = EndpointResolver(provider)
        ep = resolver.resolve("GET", "/api/v1/orders/42")
        # ep.endpoint_id == "orders_get"
        # ep.operation_type == OperationType.OBJECT_READ
    """

    def __init__(self, provider: "RuntimeConfigProvider") -> None:
        self._provider = provider

    def resolve(self, method: str, path: str) -> Optional[EffectiveEndpoint]:
        """Find the EffectiveEndpoint for this (method, path).

        Returns None when:
          - No catalog entry matches.
          - The matched endpoint is disabled (enabled=False).
          - Any internal error occurs.

        Never raises.
        """
        try:
            config = self._provider.get_config()
            return self._resolve_against(config, method, path)
        except Exception as exc:
            logger.debug(
                "EndpointResolver.resolve(%r, %r) error: %s", method, path, exc
            )
            return None

    def resolve_including_disabled(self, method: str, path: str) -> Optional[EffectiveEndpoint]:
        """Like resolve(), but also returns disabled endpoints.

        Useful for the panel to show which catalog entries cover a given path.
        """
        try:
            config = self._provider.get_config()
            ep = self._find_best_match(config, method, path)
            return ep
        except Exception:
            return None

    # ── Private matching logic ────────────────────────────────────────────────

    def _resolve_against(
        self, config: EffectiveRuntimeConfig, method: str, path: str
    ) -> Optional[EffectiveEndpoint]:
        ep = self._find_best_match(config, method, path)
        if ep is None:
            return None
        if not ep.enabled:
            logger.debug(
                "EndpointResolver: matched endpoint '%s' is disabled; returning None",
                ep.endpoint_id,
            )
            return None
        return ep

    def _find_best_match(
        self, config: EffectiveRuntimeConfig, method: str, path: str
    ) -> Optional[EffectiveEndpoint]:
        """Find best-matching EffectiveEndpoint regardless of enabled state."""
        method_upper = method.upper()

        # Phase 1: exact path + method match (O(n) but fast for small catalogs)
        for ep in config.endpoints.values():
            if ep.method.value == method_upper and ep.path_pattern == path:
                return ep

        # Phase 2: pattern match — collect all matches, pick highest specificity
        best: Optional[EffectiveEndpoint] = None
        best_score = -1

        for ep in config.endpoints.values():
            if ep.method.value != method_upper:
                continue
            if not _PARAM_RE.search(ep.path_pattern):
                continue  # no params → would have matched in Phase 1 if it was a match
            if _pattern_matches(ep.path_pattern, path):
                score = _specificity_score(ep.path_pattern)
                if score > best_score:
                    best = ep
                    best_score = score

        return best

    # ── Batch resolution (for panel / diagnostics) ───────────────────────────

    def resolve_all(self) -> list[EffectiveEndpoint]:
        """Return all EffectiveEndpoints in the current config.

        Useful for the panel to list what's available without hitting a specific path.
        """
        try:
            return list(self._provider.get_config().endpoints.values())
        except Exception:
            return []

    def coverage_report(self, paths: list[tuple[str, str]]) -> list[dict]:
        """For each (method, path), report whether a catalog entry exists.

        Used for migration analysis: pass the list of hardcoded routes from
        honeypot_public.py to see which ones have catalog coverage.
        """
        results = []
        for method, path in paths:
            ep = self.resolve_including_disabled(method, path)
            results.append({
                "method": method,
                "path": path,
                "endpoint_id": ep.endpoint_id if ep else None,
                "operation_type": ep.operation_type.value if ep else None,
                "has_flaw": ep.flaw is not None if ep else False,
                "enabled": ep.enabled if ep else None,
            })
        return results
