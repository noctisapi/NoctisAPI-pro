from __future__ import annotations

import fnmatch
import hashlib
import json
import random
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional


RESPONSE_MODES = {"normal", "minimal", "error_bias"}
MUTATION_POLICIES = {"none", "daily", "weekly"}

DEFAULT_ENDPOINT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "response_mode": "normal",
    "fixed_status": None,
    "richness_level": 2,
}

CORE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "balanced": {
        "enabled": True,
        "response_mode": "normal",
        "fixed_status": None,
        "richness_level": 2,
    },
    "minimal": {
        "enabled": True,
        "response_mode": "minimal",
        "fixed_status": None,
        "richness_level": 0,
    },
    "error_trap": {
        "enabled": True,
        "response_mode": "error_bias",
        "fixed_status": None,
        "richness_level": 1,
    },
    "disabled": {
        "enabled": False,
        "response_mode": "normal",
        "fixed_status": 404,
        "richness_level": 0,
    },
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _clamp_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(low, min(high, parsed))


def _parse_ts(ts: str) -> Optional[datetime]:
    raw = str(ts or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize_method(method: Any) -> str:
    raw = str(method or "*").strip().upper()
    if not raw:
        return "*"
    return raw


def _normalize_path(path: Any) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        return "/" + raw
    return raw


def _path_segment_match(config_segment: str, actual_segment: str) -> bool:
    cfg = str(config_segment or "")
    act = str(actual_segment or "")
    if not cfg:
        return cfg == act
    if cfg.startswith("{") and cfg.endswith("}") and len(cfg) > 2:
        return bool(act)
    return cfg == act


def path_matches_pattern(config_path: str, request_path: str) -> bool:
    cfg = _normalize_path(config_path)
    req = _normalize_path(request_path)
    if cfg == req:
        return True
    if "*" in cfg or "?" in cfg:
        return bool(fnmatch.fnmatch(req, cfg))

    cfg_parts = cfg.strip("/").split("/") if cfg != "/" else []
    req_parts = req.strip("/").split("/") if req != "/" else []
    if len(cfg_parts) != len(req_parts):
        return False
    for cfg_seg, req_seg in zip(cfg_parts, req_parts):
        if not _path_segment_match(cfg_seg, req_seg):
            return False
    return True


def _path_specificity_score(path_pattern: str) -> tuple[int, int, int, int]:
    path = _normalize_path(path_pattern)
    if path == "/":
        return (0, 1, 0, 1)
    parts = path.strip("/").split("/")
    literal_count = 0
    template_count = 0
    wildcard_count = 0
    for part in parts:
        if "*" in part or "?" in part:
            wildcard_count += 1
        elif part.startswith("{") and part.endswith("}") and len(part) > 2:
            template_count += 1
        else:
            literal_count += 1
    return (literal_count, -template_count, -wildcard_count, len(path))


def _normalize_response_mode(value: Any) -> str:
    raw = str(value or DEFAULT_ENDPOINT_CONFIG["response_mode"]).strip().lower()
    if raw not in RESPONSE_MODES:
        return str(DEFAULT_ENDPOINT_CONFIG["response_mode"])
    return raw


def _normalize_policy(value: Any) -> str:
    raw = str(value or "none").strip().lower()
    if raw not in MUTATION_POLICIES:
        return "none"
    return raw


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except Exception:
        return set()
    out: set[str] = set()
    for row in rows:
        try:
            out.add(str(row["name"]))
        except Exception:
            try:
                out.add(str(row[1]))
            except Exception:
                continue
    return out


def _ensure_columns(conn: sqlite3.Connection, table: str, expected: Dict[str, str]) -> None:
    existing = _table_columns(conn, table)
    for column, ddl in expected.items():
        if column in existing:
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_endpoint_configs (
          method TEXT NOT NULL,
          path TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          response_mode TEXT NOT NULL DEFAULT 'normal',
          fixed_status INTEGER,
          richness_level INTEGER NOT NULL DEFAULT 2,
          updated_ts TEXT NOT NULL,
          PRIMARY KEY(method, path)
        )
        """
    )
    _ensure_columns(
        conn,
        "api_endpoint_configs",
        {
            "method": "TEXT NOT NULL DEFAULT '*'",
            "path": "TEXT NOT NULL DEFAULT '/'",
            "enabled": "INTEGER NOT NULL DEFAULT 1",
            "response_mode": "TEXT NOT NULL DEFAULT 'normal'",
            "fixed_status": "INTEGER",
            "richness_level": "INTEGER NOT NULL DEFAULT 2",
            "updated_ts": "TEXT NOT NULL DEFAULT ''",
        },
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_mutation_settings (
          singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
          mutation_policy TEXT NOT NULL DEFAULT 'none',
          mutation_intensity INTEGER NOT NULL DEFAULT 0,
          updated_ts TEXT NOT NULL
        )
        """
    )
    _ensure_columns(
        conn,
        "api_mutation_settings",
        {
            "singleton_id": "INTEGER",
            "mutation_policy": "TEXT NOT NULL DEFAULT 'none'",
            "mutation_intensity": "INTEGER NOT NULL DEFAULT 0",
            "updated_ts": "TEXT NOT NULL DEFAULT ''",
        },
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          enabled INTEGER NOT NULL DEFAULT 1,
          match_path TEXT,
          match_method TEXT,
          match_user_agent TEXT,
          action_change_richness INTEGER,
          action_force_status INTEGER,
          action_increase_latency INTEGER,
          created_ts TEXT NOT NULL,
          updated_ts TEXT NOT NULL
        )
        """
    )
    _ensure_columns(
        conn,
        "api_rules",
        {
            "id": "INTEGER",
            "enabled": "INTEGER NOT NULL DEFAULT 1",
            "match_path": "TEXT",
            "match_method": "TEXT",
            "match_user_agent": "TEXT",
            "action_change_richness": "INTEGER",
            "action_force_status": "INTEGER",
            "action_increase_latency": "INTEGER",
            "created_ts": "TEXT NOT NULL DEFAULT ''",
            "updated_ts": "TEXT NOT NULL DEFAULT ''",
        },
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_rules_enabled ON api_rules(enabled, id)")
    conn.execute(
        """
        INSERT OR IGNORE INTO api_mutation_settings(singleton_id, mutation_policy, mutation_intensity, updated_ts)
        VALUES(1, 'none', 0, ?)
        """,
        (_utc_now_iso(),),
    )
    conn.commit()


def sanitize_endpoint_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(raw or {})
    enabled = bool(payload.get("enabled", True))
    response_mode = _normalize_response_mode(payload.get("response_mode"))
    richness_level = _clamp_int(payload.get("richness_level"), 0, 2, 2)
    fixed_status_raw = payload.get("fixed_status")
    fixed_status = None
    if fixed_status_raw is not None and str(fixed_status_raw).strip() != "":
        fixed_status = _clamp_int(fixed_status_raw, 100, 599, 500)
    return {
        "enabled": enabled,
        "response_mode": response_mode,
        "fixed_status": fixed_status,
        "richness_level": richness_level,
    }


def list_templates() -> Dict[str, Dict[str, Any]]:
    return {name: dict(cfg) for name, cfg in CORE_TEMPLATES.items()}


def list_endpoint_configs(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    ensure_tables(conn)
    rows = conn.execute(
        """
        SELECT method, path, enabled, response_mode, fixed_status, richness_level, updated_ts
        FROM api_endpoint_configs
        ORDER BY path ASC, method ASC
        """
    ).fetchall()
    items: List[Dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "method": str(row["method"] or "*"),
                "path": str(row["path"] or "/"),
                "config": {
                    "enabled": bool(int(row["enabled"] or 0)),
                    "response_mode": _normalize_response_mode(row["response_mode"]),
                    "fixed_status": int(row["fixed_status"]) if row["fixed_status"] is not None else None,
                    "richness_level": _clamp_int(row["richness_level"], 0, 2, 2),
                },
                "updated_ts": row["updated_ts"],
            }
        )
    return items


def upsert_endpoint_config(conn: sqlite3.Connection, *, path: str, method: str = "*", config: Dict[str, Any]) -> Dict[str, Any]:
    ensure_tables(conn)
    normalized_path = _normalize_path(path)
    normalized_method = _normalize_method(method)
    cfg = sanitize_endpoint_config(config)
    now = _utc_now_iso()
    cur = conn.execute(
        """
        UPDATE api_endpoint_configs
        SET enabled=?, response_mode=?, fixed_status=?, richness_level=?, updated_ts=?
        WHERE method=? AND path=?
        """,
        (
            1 if cfg["enabled"] else 0,
            cfg["response_mode"],
            cfg["fixed_status"],
            int(cfg["richness_level"]),
            now,
            normalized_method,
            normalized_path,
        ),
    )
    if int(cur.rowcount or 0) <= 0:
        conn.execute(
            """
            INSERT INTO api_endpoint_configs(method, path, enabled, response_mode, fixed_status, richness_level, updated_ts)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                normalized_method,
                normalized_path,
                1 if cfg["enabled"] else 0,
                cfg["response_mode"],
                cfg["fixed_status"],
                int(cfg["richness_level"]),
                now,
            ),
        )
    conn.commit()
    return {"method": normalized_method, "path": normalized_path, "config": cfg, "updated_ts": now}


def delete_endpoint_config(conn: sqlite3.Connection, *, path: str, method: str = "*") -> bool:
    ensure_tables(conn)
    normalized_path = _normalize_path(path)
    normalized_method = _normalize_method(method)
    cur = conn.execute(
        "DELETE FROM api_endpoint_configs WHERE method=? AND path=?",
        (normalized_method, normalized_path),
    )
    conn.commit()
    return bool(cur.rowcount)


def apply_template(
    conn: sqlite3.Connection,
    *,
    template_name: str,
    path: str,
    method: str = "*",
) -> Dict[str, Any]:
    template = CORE_TEMPLATES.get(str(template_name or "").strip().lower())
    if not template:
        raise ValueError("unknown_template")
    return upsert_endpoint_config(conn, path=path, method=method, config=template)


def resolve_endpoint_config(conn: sqlite3.Connection, *, path: str, method: str) -> Dict[str, Any]:
    ensure_tables(conn)
    normalized_path = _normalize_path(path)
    normalized_method = _normalize_method(method)
    rows = conn.execute(
        """
        SELECT method, path, enabled, response_mode, fixed_status, richness_level
        FROM api_endpoint_configs
        WHERE method IN (?, '*')
        """,
        (normalized_method,),
    ).fetchall()
    best_row: Optional[sqlite3.Row] = None
    best_key: Optional[tuple[Any, ...]] = None
    best_match_type = "default"
    for row in rows:
        row_method = _normalize_method(row["method"] or "*")
        row_path = _normalize_path(row["path"] or "/")
        if not path_matches_pattern(row_path, normalized_path):
            continue
        method_rank = 0 if row_method == normalized_method else 1
        path_rank = 0 if row_path == normalized_path else 1
        spec = _path_specificity_score(row_path)
        key = (method_rank, path_rank, -spec[0], -spec[1], -spec[2], -spec[3])
        if best_key is None or key < best_key:
            best_key = key
            best_row = row
            if path_rank == 0 and method_rank == 0:
                best_match_type = "exact"
            elif path_rank == 0:
                best_match_type = "exact_path_any_method"
            elif method_rank == 0:
                best_match_type = "pattern_same_method"
            else:
                best_match_type = "pattern_any_method"

    if not best_row:
        return {
            "config": dict(DEFAULT_ENDPOINT_CONFIG),
            "match_type": "default",
        }
    return {
        "config": {
            "enabled": bool(int(best_row["enabled"] or 0)),
            "response_mode": _normalize_response_mode(best_row["response_mode"]),
            "fixed_status": int(best_row["fixed_status"]) if best_row["fixed_status"] is not None else None,
            "richness_level": _clamp_int(best_row["richness_level"], 0, 2, 2),
        },
        "match_type": best_match_type,
    }


def get_mutation_config(conn: sqlite3.Connection) -> Dict[str, Any]:
    ensure_tables(conn)
    row = conn.execute(
        """
        SELECT mutation_policy, mutation_intensity, updated_ts
        FROM api_mutation_settings
        WHERE singleton_id=1
        """
    ).fetchone()
    if not row:
        return {"mutation_policy": "none", "mutation_intensity": 0, "updated_ts": _utc_now_iso()}
    return {
        "mutation_policy": _normalize_policy(row["mutation_policy"]),
        "mutation_intensity": _clamp_int(row["mutation_intensity"], 0, 3, 0),
        "updated_ts": row["updated_ts"],
    }


def set_mutation_config(conn: sqlite3.Connection, *, mutation_policy: str, mutation_intensity: int) -> Dict[str, Any]:
    ensure_tables(conn)
    policy = _normalize_policy(mutation_policy)
    intensity = _clamp_int(mutation_intensity, 0, 3, 0)
    now = _utc_now_iso()
    conn.execute(
        """
        UPDATE api_mutation_settings
        SET mutation_policy=?, mutation_intensity=?, updated_ts=?
        WHERE singleton_id=1
        """,
        (policy, int(intensity), now),
    )
    conn.commit()
    return {"mutation_policy": policy, "mutation_intensity": intensity, "updated_ts": now}


def _sanitize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(rule or {})
    match = payload.get("match") if isinstance(payload.get("match"), dict) else {}
    action = payload.get("action") if isinstance(payload.get("action"), dict) else {}

    match_path = str(match.get("path") or "").strip()
    match_method = _normalize_method(match.get("method") or "*")
    match_user_agent = str(match.get("user_agent") or "").strip()

    if match_path and not match_path.startswith("/"):
        match_path = "/" + match_path

    change_richness = action.get("change_richness")
    if change_richness is not None and str(change_richness).strip() != "":
        change_richness = _clamp_int(change_richness, -2, 2, 0)
    else:
        change_richness = None

    force_status = action.get("force_status")
    if force_status is not None and str(force_status).strip() != "":
        force_status = _clamp_int(force_status, 100, 599, 500)
    else:
        force_status = None

    increase_latency = action.get("increase_latency")
    if increase_latency is not None and str(increase_latency).strip() != "":
        increase_latency = _clamp_int(increase_latency, 0, 5000, 0)
    else:
        increase_latency = None

    return {
        "enabled": bool(payload.get("enabled", True)),
        "match": {
            "path": match_path,
            "method": match_method,
            "user_agent": match_user_agent,
        },
        "action": {
            "change_richness": change_richness,
            "force_status": force_status,
            "increase_latency": increase_latency,
        },
    }


def list_rules(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    ensure_tables(conn)
    rows = conn.execute(
        """
        SELECT id, enabled, match_path, match_method, match_user_agent,
               action_change_richness, action_force_status, action_increase_latency,
               created_ts, updated_ts
        FROM api_rules
        ORDER BY id ASC
        """
    ).fetchall()
    items: List[Dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "id": int(row["id"]),
                "enabled": bool(int(row["enabled"] or 0)),
                "match": {
                    "path": str(row["match_path"] or ""),
                    "method": _normalize_method(row["match_method"] or "*"),
                    "user_agent": str(row["match_user_agent"] or ""),
                },
                "action": {
                    "change_richness": int(row["action_change_richness"])
                    if row["action_change_richness"] is not None
                    else None,
                    "force_status": int(row["action_force_status"])
                    if row["action_force_status"] is not None
                    else None,
                    "increase_latency": int(row["action_increase_latency"])
                    if row["action_increase_latency"] is not None
                    else None,
                },
                "created_ts": row["created_ts"],
                "updated_ts": row["updated_ts"],
            }
        )
    return items


def add_rule(conn: sqlite3.Connection, rule: Dict[str, Any]) -> Dict[str, Any]:
    ensure_tables(conn)
    normalized = _sanitize_rule(rule)
    now = _utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO api_rules(
          enabled, match_path, match_method, match_user_agent,
          action_change_richness, action_force_status, action_increase_latency,
          created_ts, updated_ts
        ) VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            1 if normalized["enabled"] else 0,
            normalized["match"]["path"],
            normalized["match"]["method"],
            normalized["match"]["user_agent"],
            normalized["action"]["change_richness"],
            normalized["action"]["force_status"],
            normalized["action"]["increase_latency"],
            now,
            now,
        ),
    )
    conn.commit()
    rule_id = int(cur.lastrowid or 0)
    out = dict(normalized)
    out["id"] = rule_id
    out["created_ts"] = now
    out["updated_ts"] = now
    return out


def delete_rule(conn: sqlite3.Connection, *, rule_id: int) -> bool:
    ensure_tables(conn)
    cur = conn.execute("DELETE FROM api_rules WHERE id=?", (int(rule_id),))
    conn.commit()
    return bool(cur.rowcount)


def _match_path(pattern: str, actual_path: str) -> bool:
    clean_pattern = str(pattern or "").strip()
    if not clean_pattern:
        return True
    return path_matches_pattern(clean_pattern, actual_path)


def _match_ua(pattern: str, user_agent: str) -> bool:
    clean_pattern = str(pattern or "").strip()
    if not clean_pattern:
        return True
    ua = str(user_agent or "").strip()
    if "*" in clean_pattern or "?" in clean_pattern:
        return bool(fnmatch.fnmatch(ua, clean_pattern))
    return clean_pattern.lower() in ua.lower()


def evaluate_rules(
    rules: List[Dict[str, Any]],
    *,
    path: str,
    method: str,
    user_agent: str,
) -> Dict[str, Any]:
    normalized_path = _normalize_path(path)
    normalized_method = _normalize_method(method)
    matched_ids: List[int] = []
    total_latency = 0
    richness_delta = 0
    force_status: Optional[int] = None

    for rule in rules:
        if not bool(rule.get("enabled", True)):
            continue
        match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
        action = rule.get("action") if isinstance(rule.get("action"), dict) else {}

        rule_path = str(match.get("path") or "").strip()
        rule_method = _normalize_method(match.get("method") or "*")
        rule_ua = str(match.get("user_agent") or "").strip()

        if rule_method not in ("*", normalized_method):
            continue
        if not _match_path(rule_path, normalized_path):
            continue
        if not _match_ua(rule_ua, user_agent):
            continue

        rule_id = int(rule.get("id") or 0)
        if rule_id:
            matched_ids.append(rule_id)

        if action.get("change_richness") is not None:
            richness_delta += _clamp_int(action.get("change_richness"), -2, 2, 0)
        if action.get("increase_latency") is not None:
            total_latency += _clamp_int(action.get("increase_latency"), 0, 5000, 0)
        if action.get("force_status") is not None:
            force_status = _clamp_int(action.get("force_status"), 100, 599, 500)

    return {
        "matched_rule_ids": matched_ids,
        "richness_delta": richness_delta,
        "extra_latency_ms": _clamp_int(total_latency, 0, 5000, 0),
        "force_status": force_status,
    }


def resolve_request_policy(
    conn: sqlite3.Connection,
    *,
    path: str,
    method: str,
    user_agent: str,
    pro_enabled: bool,
) -> Dict[str, Any]:
    ensure_tables(conn)
    base = resolve_endpoint_config(conn, path=path, method=method)
    effective = dict(base["config"])
    rules_eval = {
        "matched_rule_ids": [],
        "richness_delta": 0,
        "extra_latency_ms": 0,
        "force_status": None,
    }
    mutation = {"mutation_policy": "none", "mutation_intensity": 0}

    if pro_enabled:
        try:
            current_rules = list_rules(conn)
            rules_eval = evaluate_rules(
                current_rules,
                path=path,
                method=method,
                user_agent=user_agent,
            )
            if rules_eval["richness_delta"]:
                base_richness = _clamp_int(effective.get("richness_level"), 0, 2, 2)
                effective["richness_level"] = _clamp_int(
                    int(base_richness) + int(rules_eval["richness_delta"]),
                    0,
                    2,
                    2,
                )
            if rules_eval["force_status"] is not None and effective.get("fixed_status") is None:
                effective["fixed_status"] = int(rules_eval["force_status"])
            mutation = get_mutation_config(conn)
        except Exception:
            # Never lose CORE behavior because of a PRO rules/mutation read failure.
            rules_eval = {
                "matched_rule_ids": [],
                "richness_delta": 0,
                "extra_latency_ms": 0,
                "force_status": None,
            }
            mutation = {"mutation_policy": "none", "mutation_intensity": 0}

    return {
        "endpoint_config": sanitize_endpoint_config(effective),
        "endpoint_match_type": base.get("match_type", "default"),
        "rules": rules_eval,
        "latency_ms": int(rules_eval.get("extra_latency_ms") or 0),
        "mutation": mutation,
        "pro_enabled": bool(pro_enabled),
    }


def mutation_bucket(policy: str, *, now: Optional[datetime] = None) -> str:
    normalized = _normalize_policy(policy)
    if normalized == "none":
        return "none"
    current = now or _utc_now()
    if normalized == "daily":
        return current.strftime("%Y-%m-%d")
    iso_year, iso_week, _iso_day = current.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"


def _seed_value(*parts: str) -> int:
    raw = "|".join([str(part or "") for part in parts]).encode("utf-8", errors="ignore")
    return int(hashlib.sha256(raw).hexdigest()[:12], 16)


def compute_status(
    *,
    original_status: int,
    response_mode: str,
    fixed_status: Optional[int],
    mutation_policy: str,
    mutation_intensity: int,
    path: str,
    method: str,
    actor_id: str,
) -> int:
    status = int(original_status or 200)
    mode = _normalize_response_mode(response_mode)
    if mode == "error_bias" and status < 400:
        seed = _seed_value(path, method, actor_id, "error_bias")
        status = 500 if (seed % 2 == 0) else 429
    if fixed_status is not None:
        status = _clamp_int(fixed_status, 100, 599, 500)
    elif _normalize_policy(mutation_policy) != "none" and int(mutation_intensity or 0) >= 3 and status == 200:
        seed = _seed_value(path, method, actor_id, mutation_bucket(mutation_policy))
        if seed % 7 == 0:
            status = 202
    return int(status)


def _reduce_dict_richness(payload: Dict[str, Any], richness_level: int) -> Dict[str, Any]:
    if richness_level >= 2:
        return dict(payload)
    preferred = ["status", "detail", "message", "error", "id", "token", "kind", "result"]
    out: Dict[str, Any] = {}
    for key in preferred:
        if key in payload:
            out[key] = payload[key]
    if richness_level == 1:
        if len(out) < 3:
            for key, value in payload.items():
                if key not in out:
                    out[key] = value
                if len(out) >= 3:
                    break
        return out or dict(payload)
    if out:
        one = next(iter(out.items()))
        return {one[0]: one[1]}
    first_key = next(iter(payload.keys()), None)
    if first_key is not None:
        return {first_key: payload[first_key]}
    return {}


def _minimize_payload(payload: Any, richness_level: int) -> Any:
    if isinstance(payload, dict):
        if richness_level <= 0:
            if "status" in payload:
                return {"status": payload.get("status")}
            if "detail" in payload:
                return {"detail": payload.get("detail")}
            return {"ok": True}
        if int(richness_level) == 1:
            return _reduce_dict_richness(payload, 0)
        return _reduce_dict_richness(payload, 1)
    if isinstance(payload, list):
        if richness_level <= 0:
            return {"count": len(payload)}
        if int(richness_level) == 1:
            return payload[: min(len(payload), 1)]
        return payload[: min(len(payload), 3)]
    return payload


def _mutate_message(value: str, rng: random.Random, intensity: int) -> str:
    if intensity <= 0:
        return value
    text = str(value or "")
    if not text:
        return text
    variants = [
        "accepted",
        "queued",
        "scheduled",
        "delayed",
        "processed with warnings",
        "requires retry",
    ]
    marker = variants[rng.randrange(0, len(variants))]
    if intensity >= 2:
        return f"{text} ({marker})"
    return marker


def _mutate_payload_recursive(payload: Any, rng: random.Random, intensity: int) -> Any:
    if intensity <= 0:
        return payload
    if isinstance(payload, dict):
        out: Dict[str, Any] = {}
        for key, value in payload.items():
            if isinstance(value, str) and str(key).lower() in {"message", "detail", "error", "status"}:
                out[key] = _mutate_message(value, rng, intensity)
            else:
                out[key] = _mutate_payload_recursive(value, rng, intensity)
        keys = list(out.keys())
        if intensity == 1:
            keys = sorted(keys)
        elif intensity == 2:
            keys = list(reversed(keys))
        else:
            rng.shuffle(keys)
        reordered: Dict[str, Any] = {}
        for key in keys:
            reordered[key] = out[key]
        return reordered
    if isinstance(payload, list):
        out_list = [_mutate_payload_recursive(item, rng, intensity) for item in payload]
        if intensity >= 3 and len(out_list) > 1:
            rng.shuffle(out_list)
        return out_list
    return payload


def mutate_json_payload(
    payload: Any,
    *,
    response_mode: str,
    richness_level: int,
    mutation_policy: str,
    mutation_intensity: int,
    path: str,
    method: str,
    actor_id: str,
) -> Any:
    mode = _normalize_response_mode(response_mode)
    richness = _clamp_int(richness_level, 0, 2, 2)
    policy = _normalize_policy(mutation_policy)
    intensity = _clamp_int(mutation_intensity, 0, 3, 0)

    out = payload
    if mode == "minimal":
        out = _minimize_payload(out, richness)
    elif isinstance(out, dict):
        out = _reduce_dict_richness(out, richness)

    if policy != "none" and intensity > 0:
        bucket = mutation_bucket(policy)
        seed = _seed_value(path, method, actor_id, bucket, str(intensity))
        rng = random.Random(seed)
        out = _mutate_payload_recursive(out, rng, intensity)
        if isinstance(out, dict):
            out["_variant"] = {
                "policy": policy,
                "bucket": bucket,
                "intensity": intensity,
                "id": seed % 1000,
            }
    return out


def mutation_headers(
    *,
    mutation_policy: str,
    mutation_intensity: int,
    matched_rule_ids: List[int],
    path: str,
    method: str,
    actor_id: str,
) -> Dict[str, str]:
    policy = _normalize_policy(mutation_policy)
    intensity = _clamp_int(mutation_intensity, 0, 3, 0)
    headers: Dict[str, str] = {}
    if policy == "none" or intensity <= 0:
        return headers
    bucket = mutation_bucket(policy)
    seed = _seed_value(path, method, actor_id, bucket, str(intensity))
    headers["x-hp-mutation-policy"] = policy
    headers["x-hp-mutation-bucket"] = bucket
    headers["x-hp-variant"] = str(seed % 97)
    if matched_rule_ids:
        headers["x-hp-rule-hits"] = str(len(matched_rule_ids))
    if intensity >= 2:
        headers["x-hp-mutation-profile"] = "aggressive"
    return headers


def _safe_json_loads(raw: str) -> Dict[str, Any]:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except Exception:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _iter_recent_events(
    conn: sqlite3.Connection,
    *,
    window_hours: int,
    max_rows: int,
) -> List[sqlite3.Row]:
    rows = conn.execute(
        """
        SELECT id, ts, actor_id, kind, path, method, ip, ua, status, extra_json
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, int(max_rows)),),
    ).fetchall()
    now = _utc_now()
    lower_bound = now - timedelta(hours=max(1, int(window_hours)))
    filtered: List[sqlite3.Row] = []
    for row in rows:
        ts = _parse_ts(row["ts"])
        if ts is None:
            continue
        if ts < lower_bound:
            continue
        filtered.append(row)
    return filtered


def analytics_endpoint_metrics(
    conn: sqlite3.Connection,
    *,
    window_hours: int = 24,
    limit: int = 25,
    max_rows: int = 5000,
) -> List[Dict[str, Any]]:
    rows = _iter_recent_events(conn, window_hours=window_hours, max_rows=max_rows)
    buckets: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        path = _normalize_path(row["path"] or "/")
        method = _normalize_method(row["method"] or "*")
        key = f"{method} {path}"
        bucket = buckets.setdefault(
            key,
            {
                "method": method,
                "path": path,
                "hits": 0,
                "errors": 0,
                "status_sum": 0,
                "status_count": 0,
                "latency_sum": 0,
                "latency_count": 0,
                "actors": set(),
            },
        )
        bucket["hits"] += 1
        status = int(row["status"] or 0)
        if status >= 400:
            bucket["errors"] += 1
        if status > 0:
            bucket["status_sum"] += status
            bucket["status_count"] += 1
        extra = _safe_json_loads(row["extra_json"])
        latency = extra.get("latency_ms")
        if latency is not None:
            try:
                lat_val = int(latency)
            except Exception:
                lat_val = 0
            if lat_val >= 0:
                bucket["latency_sum"] += lat_val
                bucket["latency_count"] += 1
        actor_id = str(row["actor_id"] or "").strip()
        if actor_id:
            bucket["actors"].add(actor_id)

    items: List[Dict[str, Any]] = []
    for bucket in buckets.values():
        hits = int(bucket["hits"])
        errors = int(bucket["errors"])
        items.append(
            {
                "method": bucket["method"],
                "path": bucket["path"],
                "hits": hits,
                "errors": errors,
                "error_rate": round((errors / hits), 4) if hits else 0.0,
                "avg_status": round(bucket["status_sum"] / max(1, int(bucket["status_count"])), 2),
                "avg_latency_ms": round(bucket["latency_sum"] / max(1, int(bucket["latency_count"])), 2),
                "unique_actors": len(bucket["actors"]),
            }
        )
    items.sort(key=lambda x: (-int(x["hits"]), -int(x["errors"]), x["path"]))
    return items[: max(1, int(limit))]


def analytics_interest_scoring(
    conn: sqlite3.Connection,
    *,
    window_hours: int = 24,
    limit: int = 25,
    max_rows: int = 5000,
) -> List[Dict[str, Any]]:
    metrics = analytics_endpoint_metrics(
        conn,
        window_hours=window_hours,
        limit=max(1, max(limit, 50)),
        max_rows=max_rows,
    )
    sensitive_tokens = ["/admin", "/internal", "/root", "/backup", "/infra", "/cloud", "/.env"]
    for item in metrics:
        score = 0.0
        hits = float(item["hits"])
        errors = float(item["errors"])
        actors = float(item["unique_actors"])
        score += hits * 1.0
        score += errors * 2.5
        score += actors * 1.8
        path = str(item["path"] or "").lower()
        if any(tok in path for tok in sensitive_tokens):
            score += 20.0
        if item["error_rate"] >= 0.5:
            score += 8.0
        item["interest_score"] = round(score, 2)
    metrics.sort(key=lambda x: (-float(x["interest_score"]), -int(x["hits"])))
    return metrics[: max(1, int(limit))]


def analytics_fingerprinting(
    conn: sqlite3.Connection,
    *,
    window_hours: int = 24,
    limit: int = 25,
    max_rows: int = 8000,
) -> List[Dict[str, Any]]:
    rows = _iter_recent_events(conn, window_hours=window_hours, max_rows=max_rows)
    by_ip: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        ip = str(row["ip"] or "").strip() or "unknown"
        item = by_ip.setdefault(
            ip,
            {
                "ip": ip,
                "hits": 0,
                "user_agents": set(),
                "paths": set(),
                "methods": set(),
                "errors": 0,
                "actors": set(),
                "kinds": set(),
            },
        )
        item["hits"] += 1
        ua = str(row["ua"] or "").strip()
        path = _normalize_path(row["path"] or "/")
        method = _normalize_method(row["method"] or "*")
        status = int(row["status"] or 0)
        kind = str(row["kind"] or "").strip().lower()
        actor_id = str(row["actor_id"] or "").strip()

        if ua:
            item["user_agents"].add(ua)
        item["paths"].add(path)
        item["methods"].add(method)
        item["kinds"].add(kind)
        if status >= 400:
            item["errors"] += 1
        if actor_id:
            item["actors"].add(actor_id)

    findings: List[Dict[str, Any]] = []
    for item in by_ip.values():
        hits = int(item["hits"])
        ua_count = len(item["user_agents"])
        path_count = len(item["paths"])
        method_count = len(item["methods"])
        error_count = int(item["errors"])
        actor_count = len(item["actors"])
        kinds = item["kinds"]

        score = 0.0
        score += max(0, ua_count - 1) * 12.0
        score += max(0, path_count - 5) * 4.5
        score += max(0, method_count - 2) * 4.0
        score += (error_count / max(1, hits)) * 20.0
        score += max(0, actor_count - 1) * 3.0
        if any(str(kind).startswith("recon_") for kind in kinds):
            score += 10.0

        if score < 20.0:
            continue

        findings.append(
            {
                "ip": item["ip"],
                "fingerprint_score": round(score, 2),
                "hits": hits,
                "unique_user_agents": ua_count,
                "unique_paths": path_count,
                "unique_methods": method_count,
                "error_rate": round(error_count / max(1, hits), 4),
                "unique_actors": actor_count,
                "sample_paths": sorted(list(item["paths"]))[:6],
            }
        )

    findings.sort(key=lambda x: (-float(x["fingerprint_score"]), -int(x["hits"])))
    return findings[: max(1, int(limit))]
