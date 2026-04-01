"""LegacyConfigAdapter converts legacy DB state into InstanceConfig.

Read order:
1. Canonical InstanceConfig from system_settings.instance_config, if present.
2. Supplemental system_settings keys for base template / extensions / difficulty.
3. Legacy api_endpoint_configs rows, merged underneath canonical endpoint overrides.
4. Legacy api_mutation_settings / api_rules, only when canonical payload does not
   already persist the new mutation/rules blocks.

The adapter never mutates the DB.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from typing import Any, Optional

from app.catalog.registry import CatalogRegistry
from app.catalog.types import Difficulty
from app.instance_config.models import (
    EndpointConfig,
    InstanceConfig,
    MutationConfig,
    ResponseRule,
)

logger = logging.getLogger(__name__)

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
    if response_mode and response_mode in _RESPONSE_MODE_TO_PROFILE:
        return _RESPONSE_MODE_TO_PROFILE[response_mode]
    if richness_level is not None and richness_level in _RICHNESS_TO_PROFILE:
        return _RICHNESS_TO_PROFILE[richness_level]
    return None


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _read_setting(conn: sqlite3.Connection, key: str) -> Optional[str]:
    if not _table_exists(conn, "system_settings"):
        return None
    row = conn.execute(
        "SELECT value FROM system_settings WHERE key=?",
        (key,),
    ).fetchone()
    if row and row[0] is not None:
        return str(row[0])
    return None


def _read_instance_config_payload(conn: sqlite3.Connection) -> Optional[dict[str, Any]]:
    raw = _read_setting(conn, "instance_config")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except Exception as exc:
        logger.warning(
            "LegacyConfigAdapter: invalid system_settings.instance_config JSON; ignoring. Error: %s",
            exc,
        )
        return None
    if isinstance(parsed, dict):
        return parsed
    logger.warning("LegacyConfigAdapter: instance_config payload is not a JSON object; ignoring")
    return None


def _read_instance_config(conn: sqlite3.Connection) -> Optional[InstanceConfig]:
    payload = _read_instance_config_payload(conn)
    if payload is None:
        return None
    try:
        return InstanceConfig.from_dict(payload)
    except Exception as exc:
        logger.warning(
            "LegacyConfigAdapter: invalid system_settings.instance_config model; ignoring. Error: %s",
            exc,
        )
        return None


def _read_base_template(conn: sqlite3.Connection) -> Optional[str]:
    return _read_setting(conn, "hp_base_template")


def _read_enabled_extensions(conn: sqlite3.Connection) -> list[str]:
    raw = _read_setting(conn, "hp_enabled_extensions")
    if not raw:
        return []
    try:
        if raw.lstrip().startswith("["):
            parsed = json.loads(raw)
            values = parsed if isinstance(parsed, list) else []
        else:
            values = raw.split(",")
    except Exception:
        logger.warning("LegacyConfigAdapter: invalid hp_enabled_extensions value %r; ignoring", raw)
        return []

    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _read_global_difficulty(conn: sqlite3.Connection) -> Optional[Difficulty]:
    raw = (_read_setting(conn, "hp_global_difficulty") or "").strip().lower()
    if not raw:
        return None
    try:
        return Difficulty(raw)
    except ValueError:
        logger.warning("LegacyConfigAdapter: invalid hp_global_difficulty value %r; ignoring", raw)
        return None


def _read_endpoint_configs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    if not _table_exists(conn, "api_endpoint_configs"):
        return []
    rows = conn.execute(
        "SELECT method, path, enabled, response_mode, fixed_status, richness_level "
        "FROM api_endpoint_configs"
    ).fetchall()
    return [dict(row) for row in rows]


def _read_mutation_row(conn: sqlite3.Connection) -> Optional[dict[str, Any]]:
    if not _table_exists(conn, "api_mutation_settings"):
        return None
    row = conn.execute(
        "SELECT mutation_policy, mutation_intensity, updated_ts "
        "FROM api_mutation_settings WHERE singleton_id=1"
    ).fetchone()
    return dict(row) if row is not None else None


def _read_rule_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    if not _table_exists(conn, "api_rules"):
        return []
    rows = conn.execute(
        """
        SELECT id, enabled, match_path, match_method, match_user_agent,
               action_change_richness, action_force_status, action_increase_latency,
               created_ts, updated_ts
        FROM api_rules
        ORDER BY id ASC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _find_endpoint_id(
    registry: CatalogRegistry,
    method: str,
    path: str,
) -> Optional[str]:
    from app.endpoint_resolver import _pattern_matches, _specificity_score

    method_upper = method.upper()
    endpoint = registry.get_endpoint_by_path(method_upper, path)
    if endpoint:
        return endpoint.id

    best_id: Optional[str] = None
    best_score = -1
    for endpoint_def in registry.list_endpoints():
        if endpoint_def.method.value != method_upper:
            continue
        if _pattern_matches(endpoint_def.path_pattern, path):
            score = _specificity_score(endpoint_def.path_pattern)
            if score > best_score:
                best_id = endpoint_def.id
                best_score = score

    if best_id:
        return best_id

    if method_upper == "*":
        for try_method in ("GET", "POST", "PATCH", "PUT", "DELETE"):
            found = _find_endpoint_id(registry, try_method, path)
            if found:
                return found
    return None


class LegacyConfigAdapter:
    """Converts existing DB tables to InstanceConfig."""

    def __init__(self, conn: sqlite3.Connection, *, registry: CatalogRegistry) -> None:
        self._conn = conn
        self._registry = registry
        self._canonical_payload = _read_instance_config_payload(conn)
        self._canonical_instance = _read_instance_config(conn)

    def to_instance_config(self) -> InstanceConfig:
        canonical = self._resolve_canonical_instance_config()
        endpoint_configs = self._build_endpoint_configs()
        endpoint_configs.update(canonical.endpoint_configs)

        try:
            return InstanceConfig(
                base_template_id=canonical.base_template_id,
                enabled_extension_ids=list(canonical.enabled_extension_ids),
                global_difficulty=canonical.global_difficulty,
                endpoint_configs=endpoint_configs,
                mutation_config=self._resolve_mutation_config(canonical),
                response_rules=self._resolve_response_rules(canonical),
            )
        except Exception as exc:
            logger.warning(
                "LegacyConfigAdapter: failed to construct InstanceConfig: %s; using default",
                exc,
            )
            return InstanceConfig.default()

    def _resolve_canonical_instance_config(self) -> InstanceConfig:
        base_template_id = self._resolve_base_template()
        return InstanceConfig(
            base_template_id=base_template_id,
            enabled_extension_ids=self._resolve_enabled_extensions(base_template_id),
            global_difficulty=self._resolve_global_difficulty(),
            endpoint_configs=self._read_canonical_endpoint_configs(),
            mutation_config=self._read_canonical_mutation_config(),
            response_rules=self._read_canonical_response_rules(),
        )

    def _resolve_base_template(self) -> str:
        canonical = self._canonical_instance
        if canonical and self._registry.get_template(canonical.base_template_id):
            return canonical.base_template_id
        if canonical:
            logger.warning(
                "LegacyConfigAdapter: instance_config.base_template_id=%r not found in catalog; ignoring",
                canonical.base_template_id,
            )

        from_db = _read_base_template(self._conn)
        if from_db and self._registry.get_template(from_db):
            return from_db
        if from_db:
            logger.warning(
                "LegacyConfigAdapter: hp_base_template=%r not found in catalog; ignoring",
                from_db,
            )

        env_template = os.environ.get("HP_BASE_TEMPLATE", "").strip()
        if env_template and self._registry.get_template(env_template):
            return env_template
        if env_template:
            logger.warning(
                "LegacyConfigAdapter: HP_BASE_TEMPLATE=%r not found in catalog; ignoring",
                env_template,
            )

        return "ecommerce"

    def _resolve_enabled_extensions(self, base_template_id: str) -> list[str]:
        canonical = self._canonical_instance
        canonical_payload = self._canonical_payload or {}
        selected = (
            list(canonical.enabled_extension_ids)
            if canonical and "enabled_extension_ids" in canonical_payload
            else _read_enabled_extensions(self._conn)
        )

        template = self._registry.get_template(base_template_id)
        compatible = set(template.compatible_extension_ids) if template else set()
        result: list[str] = []
        seen: set[str] = set()
        for ext_id in selected:
            if ext_id in seen:
                continue
            if not self._registry.get_extension(ext_id):
                logger.warning("LegacyConfigAdapter: enabled extension %r not found in catalog; ignoring", ext_id)
                continue
            if compatible and ext_id not in compatible:
                logger.warning(
                    "LegacyConfigAdapter: extension %r is not compatible with template %r; keeping for builder validation",
                    ext_id,
                    base_template_id,
                )
            result.append(ext_id)
            seen.add(ext_id)
        return result

    def _resolve_global_difficulty(self) -> Difficulty:
        canonical_payload = self._canonical_payload or {}
        if self._canonical_instance and "global_difficulty" in canonical_payload:
            return self._canonical_instance.global_difficulty
        return _read_global_difficulty(self._conn) or Difficulty.MEDIUM

    def _read_canonical_endpoint_configs(self) -> dict[str, EndpointConfig]:
        canonical_payload = self._canonical_payload or {}
        if self._canonical_instance and "endpoint_configs" in canonical_payload:
            return dict(self._canonical_instance.endpoint_configs)
        return {}

    def _read_canonical_mutation_config(self) -> MutationConfig:
        canonical_payload = self._canonical_payload or {}
        if self._canonical_instance and "mutation_config" in canonical_payload:
            return self._canonical_instance.mutation_config
        return MutationConfig()

    def _read_canonical_response_rules(self) -> list[ResponseRule]:
        canonical_payload = self._canonical_payload or {}
        if self._canonical_instance and "response_rules" in canonical_payload:
            return list(self._canonical_instance.response_rules)
        return []

    def _resolve_mutation_config(self, canonical: InstanceConfig) -> MutationConfig:
        canonical_payload = self._canonical_payload or {}
        if "mutation_config" in canonical_payload:
            return canonical.mutation_config
        legacy_row = _read_mutation_row(self._conn)
        if not legacy_row:
            return canonical.mutation_config
        try:
            return MutationConfig(
                policy=str(legacy_row.get("mutation_policy") or "none"),
                intensity=int(legacy_row.get("mutation_intensity") or 0),
            )
        except Exception as exc:
            logger.warning("LegacyConfigAdapter: invalid legacy mutation config; ignoring. Error: %s", exc)
            return canonical.mutation_config

    def _resolve_response_rules(self, canonical: InstanceConfig) -> list[ResponseRule]:
        canonical_payload = self._canonical_payload or {}
        if "response_rules" in canonical_payload:
            return list(canonical.response_rules)
        return self._build_response_rules()

    def _build_endpoint_configs(self) -> dict[str, EndpointConfig]:
        try:
            rows = _read_endpoint_configs(self._conn)
        except Exception as exc:
            logger.warning(
                "LegacyConfigAdapter: error reading api_endpoint_configs: %s; returning empty overrides",
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
                continue

            response_profile_id = _map_response_profile(
                row.get("response_mode") or None,
                row.get("richness_level"),
            )

            valid_status: Optional[int] = None
            fixed_status = row.get("fixed_status")
            if fixed_status is not None:
                try:
                    parsed = int(fixed_status)
                    if 100 <= parsed <= 599:
                        valid_status = parsed
                except (TypeError, ValueError):
                    pass

            try:
                result[endpoint_id] = EndpointConfig(
                    endpoint_id=endpoint_id,
                    enabled=bool(row.get("enabled", True)),
                    response_profile_id=response_profile_id,
                    fixed_status=valid_status,
                )
            except Exception as exc:
                logger.debug("LegacyConfigAdapter: invalid EndpointConfig for %r: %s; skipping", endpoint_id, exc)

        if skipped:
            logger.info(
                "LegacyConfigAdapter: %d api_endpoint_configs row(s) had no catalog match and were skipped",
                skipped,
            )
        return result

    def _build_response_rules(self) -> list[ResponseRule]:
        try:
            rows = _read_rule_rows(self._conn)
        except Exception as exc:
            logger.warning("LegacyConfigAdapter: error reading api_rules: %s; returning no rules", exc)
            return []

        result: list[ResponseRule] = []
        for row in rows:
            match_path = str(row.get("match_path") or "").strip()
            match_method = str(row.get("match_method") or "*").strip().upper() or "*"
            endpoint_id = _find_endpoint_id(self._registry, match_method, match_path) if match_path else None
            if not endpoint_id:
                continue
            try:
                result.append(
                    ResponseRule.model_validate(
                        {
                            "id": f"legacy_rule_{int(row.get('id') or 0)}",
                            "enabled": bool(row.get("enabled", True)),
                            "match": {
                                "endpoint_id": endpoint_id,
                                "method": None if match_method == "*" else match_method,
                                "user_agent_contains": str(row.get("match_user_agent") or "").strip() or None,
                            },
                            "action": {
                                "richness_delta": row.get("action_change_richness"),
                                "force_status": row.get("action_force_status"),
                                "extra_latency_ms": row.get("action_increase_latency"),
                            },
                            "created_at": row.get("created_ts"),
                            "updated_at": row.get("updated_ts"),
                        }
                    )
                )
            except Exception as exc:
                logger.debug("LegacyConfigAdapter: invalid legacy rule %r skipped: %s", row.get("id"), exc)
        return result

    def migration_report(self) -> dict:
        try:
            endpoint_rows = _read_endpoint_configs(self._conn)
        except Exception:
            endpoint_rows = []

        mapped = []
        unmapped = []
        for row in endpoint_rows:
            method = str(row.get("method") or "*").strip()
            path = str(row.get("path") or "").strip()
            endpoint_id = _find_endpoint_id(self._registry, method, path)
            entry = {"method": method, "path": path, "endpoint_id": endpoint_id}
            if endpoint_id:
                mapped.append(entry)
            else:
                unmapped.append(entry)

        mapped_rules = []
        unmapped_rules = []
        for row in _read_rule_rows(self._conn):
            match_path = str(row.get("match_path") or "").strip()
            match_method = str(row.get("match_method") or "*").strip().upper() or "*"
            endpoint_id = _find_endpoint_id(self._registry, match_method, match_path) if match_path else None
            entry = {
                "id": int(row.get("id") or 0),
                "method": match_method,
                "path": match_path,
                "endpoint_id": endpoint_id,
            }
            if endpoint_id:
                mapped_rules.append(entry)
            else:
                unmapped_rules.append(entry)

        return {
            "total_legacy_rows": len(endpoint_rows),
            "mapped": mapped,
            "unmapped": unmapped,
            "unmapped_count": len(unmapped),
            "legacy_rule_count": len(mapped_rules) + len(unmapped_rules),
            "mapped_rule_count": len(mapped_rules),
            "unmapped_rule_count": len(unmapped_rules),
            "canonical_instance_config_present": self._canonical_instance is not None,
            "canonical_endpoint_overrides": len(self._canonical_instance.endpoint_configs) if self._canonical_instance else 0,
            "note": (
                "Unmapped rows still require catalog alignment before the legacy tables can be removed."
            ),
        }
