"""Runtime-native request policy evaluation."""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timezone
from typing import Any, Optional

from app.catalog.types import Difficulty
from app.runtime.models import EffectiveEndpoint, EffectiveRuntimeConfig


def _clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return int(default)
    return max(minimum, min(maximum, parsed))


def _normalize_response_mode(value: Any) -> str:
    mode = str(value or "normal").strip().lower()
    return mode if mode in {"normal", "minimal", "error_bias"} else "normal"


def _normalize_policy(value: Any) -> str:
    policy = str(value or "none").strip().lower()
    return policy if policy in {"none", "daily", "weekly"} else "none"


def _seed_value(*parts: str) -> int:
    raw = "|".join([str(part or "") for part in parts]).encode("utf-8", errors="ignore")
    return int(hashlib.sha256(raw).hexdigest()[:12], 16)


def response_mode_for_endpoint(endpoint: EffectiveEndpoint) -> str:
    profile_id = endpoint.response.profile_id or ""
    if profile_id.startswith("error_trap"):
        return "error_bias"
    if endpoint.response.difficulty == Difficulty.BASIC:
        return "minimal"
    return "normal"


def mutation_bucket(policy: str, *, now: Optional[datetime] = None) -> str:
    normalized = _normalize_policy(policy)
    if normalized == "none":
        return "none"
    current = now or datetime.now(timezone.utc)
    if normalized == "daily":
        return current.strftime("%Y-%m-%d")
    iso_year, iso_week, _ = current.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"


def evaluate_rules(
    runtime_config: EffectiveRuntimeConfig,
    *,
    endpoint: EffectiveEndpoint,
    method: str,
    user_agent: str,
) -> dict[str, Any]:
    normalized_method = str(method or "").strip().upper()
    normalized_ua = str(user_agent or "")
    matched_ids: list[str] = []
    total_latency = 0
    richness_delta = 0
    force_status: Optional[int] = None

    for rule in runtime_config.response_rules:
        if not rule.enabled:
            continue
        match = rule.match
        if match.endpoint_id and match.endpoint_id != endpoint.endpoint_id:
            continue
        if match.endpoint_group_id and match.endpoint_group_id not in endpoint.group_ids:
            continue
        if match.method and match.method != normalized_method:
            continue
        if match.user_agent_contains and match.user_agent_contains.lower() not in normalized_ua.lower():
            continue

        matched_ids.append(rule.id)
        if rule.action.richness_delta is not None:
            richness_delta += _clamp_int(rule.action.richness_delta, -2, 2, 0)
        if rule.action.extra_latency_ms is not None:
            total_latency += _clamp_int(rule.action.extra_latency_ms, 0, 5000, 0)
        if rule.action.force_status is not None:
            force_status = _clamp_int(rule.action.force_status, 100, 599, 500)

    return {
        "matched_rule_ids": matched_ids,
        "richness_delta": richness_delta,
        "extra_latency_ms": _clamp_int(total_latency, 0, 5000, 0),
        "force_status": force_status,
    }


def resolve_runtime_request_policy(
    runtime_config: EffectiveRuntimeConfig,
    *,
    endpoint: Optional[EffectiveEndpoint],
    path: str,
    method: str,
    user_agent: str,
    pro_enabled: bool,
) -> dict[str, Any]:
    if endpoint is None:
        return {
            "endpoint_id": None,
            "endpoint_config": {
                "enabled": True,
                "response_mode": "normal",
                "fixed_status": None,
                "richness_level": 2,
            },
            "endpoint_match_type": "default",
            "rules": {
                "matched_rule_ids": [],
                "richness_delta": 0,
                "extra_latency_ms": 0,
                "force_status": None,
            },
            "latency_ms": 0,
            "mutation": {"mutation_policy": "none", "mutation_intensity": 0},
            "pro_enabled": bool(pro_enabled),
            "source": "runtime",
            "error": "",
        }

    endpoint_config = {
        "enabled": bool(endpoint.enabled),
        "response_mode": response_mode_for_endpoint(endpoint),
        "fixed_status": endpoint.response.fixed_status,
        "richness_level": _clamp_int(endpoint.response.richness_level, 0, 2, 2),
    }
    rules = {
        "matched_rule_ids": [],
        "richness_delta": 0,
        "extra_latency_ms": 0,
        "force_status": None,
    }
    mutation = {"mutation_policy": "none", "mutation_intensity": 0}

    if pro_enabled:
        rules = evaluate_rules(
            runtime_config,
            endpoint=endpoint,
            method=method,
            user_agent=user_agent,
        )
        endpoint_config["richness_level"] = _clamp_int(
            int(endpoint_config["richness_level"]) + int(rules["richness_delta"]),
            0,
            2,
            2,
        )
        if rules["force_status"] is not None and endpoint_config["fixed_status"] is None:
            endpoint_config["fixed_status"] = int(rules["force_status"])
        mutation = runtime_config.mutation_config.to_legacy_dict()

    return {
        "endpoint_id": endpoint.endpoint_id,
        "endpoint_config": endpoint_config,
        "endpoint_match_type": "endpoint_override" if endpoint.has_instance_override else "default",
        "rules": rules,
        "latency_ms": int(rules.get("extra_latency_ms") or 0),
        "mutation": mutation,
        "pro_enabled": bool(pro_enabled),
        "source": "runtime",
        "error": "",
        "path": path,
    }


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


def _reduce_dict_richness(payload: dict[str, Any], richness_level: int) -> dict[str, Any]:
    if richness_level >= 2:
        return dict(payload)
    preferred = ["status", "detail", "message", "error", "id", "token", "kind", "result"]
    out: dict[str, Any] = {}
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
        first_key, first_value = next(iter(out.items()))
        return {first_key: first_value}
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
        out: dict[str, Any] = {}
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
        return {key: out[key] for key in keys}
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
    return out


def mutation_headers(
    *,
    mutation_policy: str,
    mutation_intensity: int,
    matched_rule_ids: list[str],
    path: str,
    method: str,
    actor_id: str,
) -> dict[str, str]:
    _ = (mutation_policy, mutation_intensity, matched_rule_ids, path, method, actor_id)
    return {}
