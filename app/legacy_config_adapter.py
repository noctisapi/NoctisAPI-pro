"""LegacyConfigAdapter — converts the existing DB schema to the new domain model.

WHAT IT DOES:
  Reads from the existing api_endpoint_configs table (and system_settings)
  and produces an InstanceConfig that the builder can consume.

WHAT IT DOES NOT DO:
  - Modify any DB table.
  - Block if DB is unavailable (caller catches exceptions).
  - Map mutation settings or rules (that is Phase 2 / ResponseFactory territory).
  - Guarantee a 1:1 mapping for every legacy row (unmapped rows are skipped with a warning).

MAPPING RULES:
  api_endpoint_configs (method, path)       →  EndpointConfig (endpoint_id)
  ─────────────────────────────────────────────────────────────────────────
  enabled = 0 / 1                           →  enabled = False / True
  response_mode = "normal"                  →  response_profile_id = "standard_medium"
  response_mode = "minimal"                 →  response_profile_id = "standard_basic"
  response_mode = "error_bias"              →  response_profile_id = "error_trap_medium"
  richness_level = 3 (override only)        →  response_profile_id = "standard_advanced"
  fixed_status != NULL                      →  fixed_status = <value>
  (path, method) → CatalogRegistry lookup  →  endpoint_id

  system_settings key "hp_base_template"   →  InstanceConfig.base_template_id
  (falls back to env HP_BASE_TEMPLATE, then "ecommerce")

LIMITATIONS (explicit, for next phase):
  - api_mutation_settings (mutation_policy, mutation_intensity) → NOT mapped.
  - api_rules → NOT mapped.
  - Paths in api_endpoint_configs that don't match any catalog entry → skipped.
  - Wildcard method "*" entries → applied to all catalog entries at that path (best-effort).
"""
from __future__ import annotations

import logging
import os
import sqlite3
from typing import Any, Optional

from app.catalog.registry import CatalogRegistry
from app.instance_config.models import EndpointConfig, InstanceConfig

logger = logging.getLogger(__name__)

# ── Profile mapping ───────────────────────────────────────────────────────────

_RESPONSE_MODE_TO_PROFILE: dict[str, str] = {
    "normal": "standard_medium",
    "minimal": "standard_basic",
    "error_bias": "error_trap_medium",
}

_RICHNESS_TO_PROFILE: dict[int, str] = {
    0: "standard_basic",
    1: "standard_basic",
    2: "standard_medium",
    3: "standard_advanced",
}


def _map_response_profile(
    response_mode: Optional[str],
    richness_level: Optional[int],
) -> Optional[str]:
    """Derive a response_profile_id from legacy response_mode + richness_level.

    Priority:
      1. response_mode (explicit setting)
      2. richness_level (fallback if mode is absent/null)
      3. None (use catalog/template default)
    """
    if response_mode and response_mode in _RESPONSE_MODE_TO_PROFILE:
        return _RESPONSE_MODE_TO_PROFILE[response_mode]
    if richness_level is not None and richness_level in _RICHNESS_TO_PROFILE:
        return _RICHNESS_TO_PROFILE[richness_level]
    return None


# ── DB helpers ────────────────────────────────────────────────────────────────

def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _read_endpoint_configs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Read all rows from api_endpoint_configs.

    Returns empty list if the table does not exist (fresh install before first startup).
    """
    if not _table_exists(conn, "api_endpoint_configs"):
        logger.debug("LegacyConfigAdapter: api_endpoint_configs table does not exist yet")
        return []
    rows = conn.execute(
        "SELECT method, path, enabled, response_mode, fixed_status, richness_level "
        "FROM api_endpoint_configs"
    ).fetchall()
    return [dict(r) for r in rows]


def _read_base_template(conn: sqlite3.Connection) -> Optional[str]:
    """Read hp_base_template from system_settings, if it exists."""
    if not _table_exists(conn, "system_settings"):
        return None
    row = conn.execute(
        "SELECT value FROM system_settings WHERE key='hp_base_template'"
    ).fetchone()
    if row and row[0]:
        return row[0]
    return None


# ── Path → endpoint_id mapping ────────────────────────────────────────────────

def _find_endpoint_id(
    registry: CatalogRegistry,
    method: str,
    path: str,
) -> Optional[str]:
    """Find the endpoint_id in the catalog that best matches (method, path).

    Strategy:
      1. Exact (method, path) lookup in registry path index.
      2. Pattern match: iterate all catalog endpoints, find one whose path_pattern
         matches the legacy literal path (handles stored patterns like /api/v1/users).
      3. Wildcard method ("*"): try GET, POST, PATCH, PUT, DELETE.

    Returns endpoint_id or None if no match.
    """
    from app.endpoint_resolver import _pattern_matches, _specificity_score

    method_upper = method.upper()

    # 1. Exact lookup
    ep = registry.get_endpoint_by_path(method_upper, path)
    if ep:
        return ep.id

    # 2. Pattern match (catalog pattern → legacy literal path)
    #    e.g. catalog has "/api/v1/orders/{order_id}", legacy stored "/api/v1/orders/123"
    #    OR   catalog has "/api/v1/orders", legacy stored "/api/v1/orders"
    best_id: Optional[str] = None
    best_score = -1

    candidates = list(registry._endpoints.values())  # access internal dict (read-only)
    for ep_def in candidates:
        if ep_def.method.value != method_upper:
            continue
        if _pattern_matches(ep_def.path_pattern, path):
            score = _specificity_score(ep_def.path_pattern)
            if score > best_score:
                best_id = ep_def.id
                best_score = score

    if best_id:
        return best_id

    # 3. Wildcard method — try all methods
    if method_upper == "*":
        for try_method in ("GET", "POST", "PATCH", "PUT", "DELETE"):
            found = _find_endpoint_id(registry, try_method, path)
            if found:
                logger.debug(
                    "LegacyConfigAdapter: wildcard method entry %r matched endpoint '%s' "
                    "via method=%s",
                    path, found, try_method,
                )
                return found

    return None


# ── Main adapter class ────────────────────────────────────────────────────────

class LegacyConfigAdapter:
    """Converts existing DB tables to a new InstanceConfig.

    Usage:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        instance_config = LegacyConfigAdapter(conn, registry=registry).to_instance_config()
        conn.close()
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        registry: CatalogRegistry,
    ) -> None:
        self._conn = conn
        self._registry = registry

    def to_instance_config(self) -> InstanceConfig:
        """Build InstanceConfig from current DB state.

        Returns InstanceConfig.default() on any DB error (never raises).
        """
        # Base template: system_settings → env var → "ecommerce"
        base_template_id = self._resolve_base_template()

        # Per-endpoint configs
        endpoint_configs = self._build_endpoint_configs()

        try:
            return InstanceConfig(
                base_template_id=base_template_id,
                enabled_extension_ids=[],   # Phase 2: read from system_settings
                endpoint_configs=endpoint_configs,
            )
        except Exception as exc:
            logger.warning(
                "LegacyConfigAdapter: failed to construct InstanceConfig: %s; "
                "using default",
                exc,
            )
            return InstanceConfig.default()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _resolve_base_template(self) -> str:
        """Determine base_template_id with fallback chain."""
        try:
            from_db = _read_base_template(self._conn)
            if from_db:
                if self._registry.get_template(from_db):
                    return from_db
                logger.warning(
                    "LegacyConfigAdapter: hp_base_template=%r not found in catalog; "
                    "ignoring",
                    from_db,
                )
        except Exception as exc:
            logger.debug("LegacyConfigAdapter: error reading hp_base_template: %s", exc)

        env_template = os.environ.get("HP_BASE_TEMPLATE", "").strip()
        if env_template:
            if self._registry.get_template(env_template):
                return env_template
            logger.warning(
                "LegacyConfigAdapter: HP_BASE_TEMPLATE=%r not found in catalog; "
                "ignoring",
                env_template,
            )

        return "ecommerce"

    def _build_endpoint_configs(self) -> dict[str, EndpointConfig]:
        """Convert api_endpoint_configs rows to EndpointConfig objects.

        Rows that cannot be mapped to a catalog endpoint_id are skipped.
        """
        try:
            rows = _read_endpoint_configs(self._conn)
        except Exception as exc:
            logger.warning(
                "LegacyConfigAdapter: error reading api_endpoint_configs: %s; "
                "returning empty overrides",
                exc,
            )
            return {}

        result: dict[str, EndpointConfig] = {}
        skipped = 0

        for row in rows:
            method = str(row.get("method") or "*").strip()
            path = str(row.get("path") or "").strip()
            if not path:
                continue

            endpoint_id = _find_endpoint_id(self._registry, method, path)
            if endpoint_id is None:
                skipped += 1
                logger.debug(
                    "LegacyConfigAdapter: no catalog entry for (%s %s); skipping",
                    method, path,
                )
                continue

            # Map fields
            enabled = bool(row.get("enabled", True))
            response_mode = row.get("response_mode") or None
            richness_level = row.get("richness_level")
            fixed_status = row.get("fixed_status")

            response_profile_id = _map_response_profile(response_mode, richness_level)

            # Validate fixed_status
            valid_status: Optional[int] = None
            if fixed_status is not None:
                try:
                    s = int(fixed_status)
                    if 100 <= s <= 599:
                        valid_status = s
                except (TypeError, ValueError):
                    pass

            try:
                cfg = EndpointConfig(
                    endpoint_id=endpoint_id,
                    enabled=enabled,
                    response_profile_id=response_profile_id,
                    fixed_status=valid_status,
                )
            except Exception as exc:
                logger.debug(
                    "LegacyConfigAdapter: invalid EndpointConfig for %r: %s; skipping",
                    endpoint_id, exc,
                )
                continue

            # Last write wins if same endpoint_id appears multiple times
            # (can happen with wildcard method "*" + specific method)
            if endpoint_id in result:
                logger.debug(
                    "LegacyConfigAdapter: duplicate mapping for endpoint_id=%r "
                    "(old: %s %s), overwriting",
                    endpoint_id, method, path,
                )
            result[endpoint_id] = cfg

        if skipped:
            logger.info(
                "LegacyConfigAdapter: %d api_endpoint_configs row(s) had no catalog "
                "match and were skipped",
                skipped,
            )

        return result

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def migration_report(self) -> dict:
        """Return a summary of what was / was not mapped. Useful for the panel."""
        try:
            rows = _read_endpoint_configs(self._conn)
        except Exception:
            rows = []

        mapped = []
        unmapped = []
        for row in rows:
            method = str(row.get("method") or "*").strip()
            path = str(row.get("path") or "").strip()
            ep_id = _find_endpoint_id(self._registry, method, path)
            entry = {"method": method, "path": path, "endpoint_id": ep_id}
            if ep_id:
                mapped.append(entry)
            else:
                unmapped.append(entry)

        return {
            "total_legacy_rows": len(rows),
            "mapped": mapped,
            "unmapped": unmapped,
            "unmapped_count": len(unmapped),
            "note": (
                "Unmapped rows are not lost — they still govern response behavior "
                "via api_modular.resolve_request_policy(). They simply have no "
                "semantic endpoint_id in the new domain yet."
            ),
        }


# ── LIMITATIONS (documented, not implemented) ─────────────────────────────────
#
# Phase 2 (ResponseFactory) will also need to adapt:
#   - api_mutation_settings  → mutation policy per endpoint or globally
#   - api_rules              → rule-based overrides
#
# Phase 3 will introduce:
#   - enabled_extension_ids  → read from system_settings key "hp_enabled_extensions"
#   - global_difficulty      → read from system_settings key "hp_global_difficulty"
