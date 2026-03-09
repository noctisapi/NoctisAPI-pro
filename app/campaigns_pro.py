from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key


PRO_STATE_TABLE = "campaign_pro_state"
PRO_STATUS_VERIFIED = "verified"
PRO_STATUS_PENDING = "pending"
PRO_STATUS_UNVERIFIED = "unverified"


class CampaignProError(RuntimeError):
    pass


def _env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        val = int(default)
    else:
        try:
            val = int(raw.strip())
        except Exception:
            val = int(default)
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


def _env_float(name: str, default: float, min_value: float | None = None, max_value: float | None = None) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        val = float(default)
    else:
        try:
            val = float(raw.strip())
        except Exception:
            val = float(default)
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _decode_b64url(s: str) -> bytes:
    raw = str(s or "").strip()
    if not raw:
        return b""
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    return base64.urlsafe_b64decode((raw + pad).encode("ascii"))


def _verify_jws_rs256_compact(jws_compact: str, public_key_pem: bytes) -> dict[str, Any]:
    parts = (jws_compact or "").strip().split(".")
    if len(parts) != 3:
        raise ValueError("invalid_jws_format")

    header_raw = _decode_b64url(parts[0])
    payload_raw = _decode_b64url(parts[1])
    signature = _decode_b64url(parts[2])
    try:
        header = json.loads(header_raw.decode("utf-8", errors="strict"))
    except Exception:
        raise ValueError("invalid_jws_header")
    if not isinstance(header, dict) or str(header.get("alg") or "") != "RS256":
        raise ValueError("invalid_jws_alg")

    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    pub = load_pem_public_key(public_key_pem)
    pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    try:
        payload = json.loads(payload_raw.decode("utf-8", errors="strict"))
    except Exception:
        raise ValueError("invalid_jws_payload")
    if not isinstance(payload, dict):
        raise ValueError("invalid_jws_payload")
    return payload


def stage_from_score(score: int) -> int:
    if score < 10:
        return 0
    if score < 20:
        return 1
    if score < 32:
        return 2
    if score < 48:
        return 3
    if score < 68:
        return 4
    if score < 92:
        return 5
    if score < 120:
        return 6
    if score < 155:
        return 7
    return 8


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex_obj(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def sha256_hex_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()


def campaign_config_from_env() -> dict[str, Any]:
    return {
        "min_features": _env_int("HP_CAMPAIGN_MIN_FEATURES", 4, 1, 50),
        "min_intersection": _env_int("HP_CAMPAIGN_MIN_INTERSECTION", 3, 1, 50),
        "min_jaccard": _env_float("HP_CAMPAIGN_MIN_JACCARD", 0.4, 0.0, 1.0),
        "max_sessions": _env_int("HP_CAMPAIGN_MAX_SESSIONS", 5, 1, 20),
        "path_ngram_top_k": _env_int("HP_CAMPAIGN_PATH_NGRAM_TOP_K", 12, 1, 40),
        "path_top_k": _env_int("HP_CAMPAIGN_PATH_TOP_K", 10, 1, 40),
        "actor_limit": _env_int("HP_CAMPAIGN_ACTOR_LIMIT", 200, 10, 500),
        "max_steps_per_session": _env_int("HP_CAMPAIGN_MAX_STEPS_PER_SESSION", 200, 20, 500),
        "max_events_per_actor": _env_int("HP_CAMPAIGN_MAX_EVENTS_PER_ACTOR", 120, 20, 500),
    }


def parse_geo_asn_from_extra(extra_json: str) -> dict[str, str]:
    try:
        obj = json.loads(extra_json or "{}")
        geo = obj.get("geo") if isinstance(obj.get("geo"), dict) else {}
        asn = obj.get("asn") if isinstance(obj.get("asn"), dict) else {}
        country = str(geo.get("country_iso2") or "").strip().upper()
        asn_org = str(asn.get("org") or asn.get("name") or "").strip()
        asn_num = str(asn.get("asn") or asn.get("number") or "").strip()
        return {"country": country, "asn": asn_num or asn_org}
    except Exception:
        return {"country": "", "asn": ""}


def build_campaigns_snapshot(conn: sqlite3.Connection, config: dict[str, Any]) -> dict[str, Any]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT actor_id, last_seen, score
        FROM actors
        ORDER BY last_seen DESC, actor_id ASC
        LIMIT ?
        """,
        (int(config["actor_limit"]),),
    )
    actor_rows = [dict(r) for r in cur.fetchall()]
    actors: list[dict[str, Any]] = []

    for row in actor_rows:
        actor_id = str(row.get("actor_id") or "")
        if not actor_id:
            continue

        last_event = cur.execute(
            "SELECT ip, ua, extra_json FROM events WHERE actor_id=? ORDER BY id DESC LIMIT 1",
            (actor_id,),
        ).fetchone()
        ip = ""
        ua = ""
        geo_country = ""
        geo_asn = ""
        if last_event:
            ip = str(last_event["ip"] or "")
            ua = str(last_event["ua"] or "")
            geo_asn_obj = parse_geo_asn_from_extra(str(last_event["extra_json"] or ""))
            geo_country = geo_asn_obj["country"]
            geo_asn = geo_asn_obj["asn"]

        sessions = []
        session_rows = cur.execute(
            """
            SELECT session_id, started_at
            FROM sessions
            WHERE actor_id=?
            ORDER BY started_at DESC, session_id ASC
            LIMIT ?
            """,
            (actor_id, int(config["max_sessions"])),
        ).fetchall()
        for sess in session_rows:
            session_id = str(sess["session_id"] or "")
            step_rows = cur.execute(
                """
                SELECT seq, ts, path, stage_before, stage_after, response_status
                FROM session_steps
                WHERE session_id=?
                ORDER BY seq ASC, id ASC
                LIMIT ?
                """,
                (session_id, int(config["max_steps_per_session"])),
            ).fetchall()
            steps = [
                {
                    "seq": int(st["seq"] or 0),
                    "ts": str(st["ts"] or ""),
                    "path": str(st["path"] or "/"),
                    "stage_before": st["stage_before"],
                    "stage_after": st["stage_after"],
                    "response_status": st["response_status"],
                }
                for st in step_rows
            ]
            sessions.append(
                {
                    "session_id": session_id,
                    "started_at": str(sess["started_at"] or ""),
                    "steps": steps,
                }
            )

        event_rows = cur.execute(
            """
            SELECT ts, path, method, kind, status, ua
            FROM events
            WHERE actor_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (actor_id, int(config["max_events_per_actor"])),
        ).fetchall()
        events = [
            {
                "ts": str(ev["ts"] or ""),
                "path": str(ev["path"] or "/"),
                "method": str(ev["method"] or ""),
                "kind": str(ev["kind"] or ""),
                "status": ev["status"],
                "ua": str(ev["ua"] or ""),
            }
            for ev in event_rows
        ]

        actors.append(
            {
                "actor_id": actor_id,
                "last_seen": str(row.get("last_seen") or ""),
                "stage": stage_from_score(int(row.get("score") or 0)),
                "ip_hash": sha256_hex_text(ip) if ip else "",
                "geo_country": geo_country,
                "geo_asn": geo_asn,
                "ua": ua,
                "sessions": sessions,
                "events": events,
            }
        )

    return {
        "schema_version": 1,
        "config": config,
        "actors": actors,
    }


def ensure_campaign_pro_state_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {PRO_STATE_TABLE} (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.commit()


def upsert_campaign_pro_state(conn: sqlite3.Connection, values: dict[str, Any]) -> None:
    ensure_campaign_pro_state_table(conn)
    cur = conn.cursor()
    for key, value in values.items():
        cur.execute(
            f"INSERT OR REPLACE INTO {PRO_STATE_TABLE}(key, value) VALUES(?, ?)",
            (str(key), str(value)),
        )
    conn.commit()


def get_campaign_pro_state(conn: sqlite3.Connection) -> dict[str, str]:
    ensure_campaign_pro_state_table(conn)
    cur = conn.cursor()
    cur.execute(f"SELECT key, value FROM {PRO_STATE_TABLE}")
    return {str(r["key"]): str(r["value"]) for r in cur.fetchall()}


def mark_campaign_status(
    conn: sqlite3.Connection,
    *,
    status: str,
    reason: str = "",
    job_id: str = "",
    snapshot_hash: str = "",
    expires_at: int | None = None,
) -> None:
    payload: dict[str, Any] = {
        "status": status,
        "reason": reason or "",
        "job_id": job_id or "",
        "snapshot_hash": snapshot_hash or "",
        "updated_at": _utc_now_iso(),
    }
    payload["expires_at"] = int(expires_at) if expires_at is not None else 0
    upsert_campaign_pro_state(conn, payload)


def campaigns_status_summary(conn: sqlite3.Connection, backend_enabled: bool) -> dict[str, Any]:
    _ = backend_enabled
    state = get_campaign_pro_state(conn)
    status = state.get("status") or ""
    if status == PRO_STATUS_VERIFIED:
        out: dict[str, Any] = {
            "status": status,
            "verified": True,
            "message": "Resultado disponible",
        }
        try:
            exp = int(state.get("expires_at") or "0")
        except Exception:
            exp = 0
        if exp > 0:
            now = int(time.time())
            if exp <= now:
                return {
                    "status": PRO_STATUS_UNVERIFIED,
                    "verified": False,
                    "message": "Resultado no disponible (expirado)",
                }
            out["expires_at"] = exp
        return out
    if status == PRO_STATUS_PENDING:
        return {"status": status, "verified": False, "message": "Recompute en progreso"}
    if status == PRO_STATUS_UNVERIFIED:
        reason = state.get("reason") or "invalido"
        return {"status": status, "verified": False, "message": f"Resultado no disponible ({reason})"}
    return {"status": "none", "verified": False, "message": "Resultado no disponible"}


def can_render_verified_campaigns(conn: sqlite3.Connection, backend_enabled: bool) -> bool:
    summary = campaigns_status_summary(conn, backend_enabled=backend_enabled)
    return bool(summary.get("verified"))


def clear_campaign_tables(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("DELETE FROM campaign_actor_links")
    cur.execute("DELETE FROM campaigns")
    conn.commit()


def apply_verified_campaign_result(conn: sqlite3.Connection, result: dict[str, Any]) -> dict[str, Any]:
    campaigns = result.get("campaigns") if isinstance(result.get("campaigns"), list) else []
    links = result.get("links") if isinstance(result.get("links"), list) else []
    metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}

    cur = conn.cursor()
    cur.execute("DELETE FROM campaign_actor_links")
    cur.execute("DELETE FROM campaigns")

    for camp in campaigns:
        if not isinstance(camp, dict):
            continue
        cur.execute(
            """
            INSERT OR REPLACE INTO campaigns(
                campaign_id, label, created_at, last_seen_at, score_avg, features_summary_json,
                representative_session_id, first_seen_at, score_det, activity_json, timeline_json,
                stage_flow_json, techniques_json, endpoints_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                str(camp.get("campaign_id") or ""),
                str(camp.get("label") or ""),
                str(camp.get("created_at") or _utc_now_iso()),
                str(camp.get("last_seen_at") or ""),
                float(camp.get("score_avg") or 0.0),
                json.dumps(camp.get("features_summary") or {}, ensure_ascii=False),
                camp.get("representative_session_id"),
                camp.get("first_seen_at"),
                int(camp.get("score_det") or 0),
                json.dumps(camp.get("activity") or {}, ensure_ascii=False),
                json.dumps(camp.get("timeline") or {}, ensure_ascii=False),
                json.dumps(camp.get("stage_flow") or {}, ensure_ascii=False),
                json.dumps(camp.get("techniques") or [], ensure_ascii=False),
                json.dumps(camp.get("endpoints") or [], ensure_ascii=False),
            ),
        )

    for link in links:
        if not isinstance(link, dict):
            continue
        cur.execute(
            "INSERT OR REPLACE INTO campaign_actor_links(campaign_id, actor_id, confidence, reasons_json, linked_at) VALUES(?,?,?,?,?)",
            (
                str(link.get("campaign_id") or ""),
                str(link.get("actor_id") or ""),
                float(link.get("confidence") or 0.0),
                json.dumps(link.get("reasons") or {}, ensure_ascii=False),
                str(link.get("linked_at") or _utc_now_iso()),
            ),
        )
    conn.commit()
    return metrics


def load_results_public_key_pem() -> bytes:
    path = (os.getenv("PRO_RESULTS_PUBLIC_KEY_PATH") or "/app/app/pro_results_public_key.pem").strip()
    with open(path, "rb") as f:
        return f.read()


def verify_signed_campaign_result(
    *,
    data: dict[str, Any],
    expected_snapshot_hash: str,
    expected_app_id: str,
    expected_instance_id: str,
    expected_license_key_hash: str,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    result = data.get("result")
    sig = str(data.get("result_sig") or "").strip()
    if not isinstance(result, dict) or not sig:
        raise CampaignProError("missing_result_or_signature")

    try:
        public_key_pem = load_results_public_key_pem()
    except Exception as exc:
        raise CampaignProError(f"results_pubkey_load_failed:{exc.__class__.__name__}")
    try:
        payload = _verify_jws_rs256_compact(sig, public_key_pem)
    except Exception as exc:
        raise CampaignProError(f"invalid_result_signature:{exc.__class__.__name__}")
    now = int(time.time())
    exp_raw = payload.get("exp")
    if exp_raw is None:
        exp_raw = payload.get("expires_at")
    try:
        exp = int(exp_raw)
    except Exception:
        raise CampaignProError("signature_missing_exp")
    if exp <= now:
        raise CampaignProError("signature_expired")

    if str(payload.get("op") or "") != "campaigns_recompute":
        raise CampaignProError("signature_op_mismatch")
    if str(payload.get("snapshot_hash") or "") != expected_snapshot_hash:
        raise CampaignProError("signature_snapshot_hash_mismatch")
    if str(payload.get("app_id") or "") != (expected_app_id or ""):
        raise CampaignProError("signature_app_id_mismatch")
    if str(payload.get("instance_id") or "") != (expected_instance_id or ""):
        raise CampaignProError("signature_instance_id_mismatch")

    payload_lkh = str(payload.get("license_key_hash") or "")
    if expected_license_key_hash and payload_lkh and payload_lkh != expected_license_key_hash:
        raise CampaignProError("signature_license_key_hash_mismatch")

    expected_result_hash = sha256_hex_obj(result)
    if str(payload.get("result_hash") or "") != expected_result_hash:
        raise CampaignProError("signature_result_hash_mismatch")

    expires_at_resp = data.get("expires_at")
    if expires_at_resp is not None:
        try:
            expires_at_resp_int = int(expires_at_resp)
        except Exception:
            raise CampaignProError("invalid_expires_at")
        if expires_at_resp_int <= now:
            raise CampaignProError("response_expired")

    return result, payload, exp
