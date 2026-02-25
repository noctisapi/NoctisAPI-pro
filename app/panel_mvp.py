# panel_mvp.py (sin auth, solo protegido por SSH tunnel)
import os
import time
import threading
import json
import sqlite3
from collections import Counter
from statistics import median
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional, List

from app import status_checks
from app import licensing
from app import campaigns_pro
from app import pro_license
from app import pro_ops
from app import license_runtime
from app import api_modular
from app.honeypot_monitor import HoneypotAvailabilityMonitor, get_history as hp_get_history, get_summary as hp_get_summary
from honey_licensing.client import compute_client_identity

APP_NAME = "noctisapi-panel"
DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")
HP_GEOIP_DB = os.getenv("HP_GEOIP_DB", "/data/GeoLite2-Country.mmdb")

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def _license_context() -> dict:
    return licensing.feature_flags()


def _has_feature(feature: licensing.Feature, *, action: str = "panel_access") -> bool:
    if not licensing.has_feature(feature):
        return False
    ok, _reason = pro_ops.authorize_pro_feature(feature=feature.value, action=action, force_refresh=False)
    return bool(ok)


def _require_feature(feature: licensing.Feature, *, action: str = "panel_access") -> None:
    if not _has_feature(feature, action=action):
        raise HTTPException(status_code=403, detail="feature not available")


def _has_modular_pro() -> bool:
    return _has_feature(licensing.Feature.API_MUTATION, action="panel_api_modular")


def _has_analytics_pro() -> bool:
    return _has_feature(licensing.Feature.ANALYTICS, action="panel_pro_analytics")


def _pro_feature_status(feature: licensing.Feature, *, action: str) -> tuple[bool, str]:
    if not licensing.has_feature(feature):
        return False, "tier_not_pro"
    ok, reason = pro_ops.authorize_pro_feature(feature=feature.value, action=action, force_refresh=False)
    return bool(ok), str(reason or "")


def _tier_has_feature(feature: licensing.Feature) -> bool:
    return bool(licensing.has_feature(feature))


def _license_runtime_snapshot() -> dict:
    return pro_license.get_backend_license_snapshot(force_refresh=False)


def _campaigns_backend_lease(*, force_refresh: bool = False) -> tuple[Optional[str], Optional[str], dict]:
    return pro_license.get_backend_lease(force_refresh=force_refresh)


def _mask_secret(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _license_error_hint(error: Optional[str]) -> str:
    code = str(error or "").strip()
    if not code:
        return ""
    if "missing_LICENSE_KEY" in code:
        return "Configura una LICENSE_KEY valida y vuelve a validar."
    if "missing_app_version" in code:
        return "Configura HP_APP_VERSION con una version no vacia."
    if "missing_PRO_BACKEND_URL" in code or "lease_transport_error" in code:
        return "Verifica PRO_BACKEND_URL y conectividad de red hacia el servidor de licencias."
    if "runtime_report_failed" in code or "runtime_report_transport_error" in code or "missing_report_backend_url" in code:
        return "Verifica HP_LICENSE_REPORT_URL (o PRO_BACKEND_URL) para reportar el estado al Licensing App."
    if "lease_missing_exp" in code:
        return "El servidor debe incluir exp o expires_at en el lease firmado."
    if "lease_missing_issued_at" in code:
        return "El servidor debe incluir issued_at o iat en el lease firmado."
    if "lease_instance_id_mismatch" in code:
        return "La licencia no esta emitida para este instance_id. Reemite/bindea usando el ID mostrado."
    if "lease_fingerprint_mismatch" in code:
        return "La licencia no coincide con el fingerprint del cliente. Reemite/bindea la licencia."
    if "lease_signature_invalid" in code:
        return "La firma no coincide con la clave publica fijada en el cliente."
    if "lease_expired" in code:
        return "La licencia esta expirada. Renuevala en el servidor de licencias."
    return "Revisa la configuracion y vuelve a validar la licencia."


def _license_config_snapshot() -> dict:
    overrides = license_runtime.load_overrides()
    identity = compute_client_identity()

    def _source(key: str) -> str:
        if str(overrides.get(key) or "").strip():
            return "override"
        raw = str(os.getenv(key) or "").strip()
        if raw:
            return "env"
        return "default"

    backend_url = campaigns_pro.pro_backend_url()
    app_id = (license_runtime.get_effective("HP_APP_ID") or os.getenv("APP_ID") or "noctisapi-pro").strip()
    app_version = (
        license_runtime.get_effective("HP_APP_VERSION")
        or os.getenv("APP_VERSION")
        or os.getenv("HP_API_VERSION")
        or ""
    ).strip()
    license_key = license_runtime.get_effective("LICENSE_KEY").strip()
    fp_override = license_runtime.get_effective("INSTANCE_FINGERPRINT_SHA256").strip()
    report_url = license_runtime.get_effective("HP_LICENSE_REPORT_URL").strip()

    return {
        "runtime_config_path": license_runtime.config_path(),
        "effective": {
            "backend_url": backend_url,
            "app_id": app_id,
            "app_version": app_version,
            "license_key_configured": bool(license_key),
            "license_key_preview": _mask_secret(license_key),
            "instance_fingerprint_sha256_override": fp_override,
            "report_url": report_url,
        },
        "sources": {
            "backend_url": _source("PRO_BACKEND_URL"),
            "report_url": _source("HP_LICENSE_REPORT_URL"),
            "app_id": _source("HP_APP_ID"),
            "app_version": _source("HP_APP_VERSION"),
            "license_key": _source("LICENSE_KEY"),
            "instance_fingerprint_sha256_override": _source("INSTANCE_FINGERPRINT_SHA256"),
        },
        "identity": identity,
    }


CAMPAIGN_JOB_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


def _env_int(name: str, default: int, min_value: Optional[int] = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except Exception:
        return default
    if min_value is not None and val < min_value:
        return min_value
    return val


def _env_float(name: str, default: float, min_value: Optional[float] = None) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        val = float(raw)
    except Exception:
        return default
    if min_value is not None and val < min_value:
        return min_value
    return val


def _is_cache_fresh(cache_ts: str, last_seen: str) -> bool:
    cache_dt = _parse_iso(cache_ts)
    last_dt = _parse_iso(last_seen)
    if not cache_dt or not last_dt:
        return False
    return cache_dt >= last_dt


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("SELECT version_num FROM alembic_version LIMIT 1")
    except sqlite3.Error as exc:
        raise RuntimeError(
            "Database schema missing Alembic migrations. Run `alembic upgrade head` before launching the admin panel."
        ) from exc


honeypot_monitor = HoneypotAvailabilityMonitor(db)


# --- Internal Health Endpoints -------------------------------------------------


@app.on_event("startup")
def _start_background_tasks():
    honeypot_monitor.start()
    licensing.set_pro_enabled_provider(pro_license.is_pro_enabled)
    pro_license.get_backend_license_snapshot(force_refresh=True)
    pro_ops.clear_cache()


@app.on_event("shutdown")
def _stop_background_tasks():
    honeypot_monitor.stop()
    licensing.set_pro_enabled_provider(None)
    pro_license.clear_cache()
    pro_ops.clear_cache()


@app.get("/health", tags=["Health"], response_class=PlainTextResponse)
def internal_health():
    try:
        status_checks.basic_health()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"status": "error", "reason": str(exc)})
    return PlainTextResponse("OK")


@app.get("/ready", tags=["Health"])
def internal_ready():
    try:
        state = status_checks.ensure_ready()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"status": "error", "reason": str(exc)})
    return JSONResponse(state)


@app.get("/admin/license", include_in_schema=False, response_class=JSONResponse)
def admin_license_status():
    """
    Internal licensing debug endpoint.

    Intended for the admin service (typically bound to 127.0.0.1 in production).
    """
    snapshot = _license_runtime_snapshot()
    identity = compute_client_identity()
    return {
        "pro_enabled": bool(snapshot.get("pro_enabled")),
        "feature_flags": licensing.feature_flags(),
        "client_identity": identity,
        "licensing": snapshot,
        "config": _license_config_snapshot(),
        "hint": _license_error_hint(snapshot.get("last_error")),
    }


@app.post("/dashboard/license/refresh", include_in_schema=False, response_class=JSONResponse)
def dashboard_license_refresh():
    payload = pro_license.get_backend_license_snapshot(force_refresh=True)
    payload["refreshed"] = bool(payload.get("valid"))
    payload["source"] = "backend"
    payload["backend_lease_ok"] = bool(payload.get("valid"))
    if payload.get("last_error"):
        payload["refresh_error"] = payload.get("last_error")
    payload["hint"] = _license_error_hint(payload.get("refresh_error") or payload.get("last_error"))
    return payload


@app.get("/dashboard/license/config", include_in_schema=False, response_class=JSONResponse)
def dashboard_license_config():
    snapshot = _license_runtime_snapshot()
    return {
        "config": _license_config_snapshot(),
        "licensing": snapshot,
        "hint": _license_error_hint(snapshot.get("last_error")),
    }


@app.post("/dashboard/license/config", include_in_schema=False, response_class=JSONResponse)
def dashboard_license_config_update(payload: dict = Body(default={})):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")

    field_map = {
        "backend_url": "PRO_BACKEND_URL",
        "report_url": "HP_LICENSE_REPORT_URL",
        "license_key": "LICENSE_KEY",
        "app_version": "HP_APP_VERSION",
        "app_id": "HP_APP_ID",
        "instance_fingerprint_sha256": "INSTANCE_FINGERPRINT_SHA256",
    }
    updates: dict[str, str] = {}
    for field, env_key in field_map.items():
        if field not in payload:
            continue
        raw = payload.get(field)
        updates[env_key] = "" if raw is None else str(raw)

    clear_all = bool(payload.get("clear_overrides"))
    try:
        if clear_all:
            license_runtime.clear_overrides()
        if updates:
            license_runtime.save_overrides(updates=updates, clear_all=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"license_config_save_failed:{exc.__class__.__name__}")

    pro_license.clear_cache()
    pro_ops.clear_cache()

    licensing_snapshot = pro_license.get_backend_license_snapshot(force_refresh=True)
    licensing_snapshot["refreshed"] = bool(licensing_snapshot.get("valid"))
    licensing_snapshot["backend_lease_ok"] = bool(licensing_snapshot.get("valid"))
    if licensing_snapshot.get("last_error"):
        licensing_snapshot["refresh_error"] = licensing_snapshot.get("last_error")
    hint = _license_error_hint(licensing_snapshot.get("refresh_error") or licensing_snapshot.get("last_error"))
    licensing_snapshot["hint"] = hint

    return {
        "saved": True,
        "config": _license_config_snapshot(),
        "licensing": licensing_snapshot,
        "hint": hint,
    }


def _honeypot_snapshot(conn: sqlite3.Connection, limit: int = 20) -> dict:
    summary = hp_get_summary(
        conn,
        honeypot_monitor.display_base_url,
        honeypot_monitor.endpoints,
        limit=limit,
    )
    processed = []
    for endpoint_summary in summary.get("endpoints") or []:
        history = endpoint_summary.get("history") or []
        for item in history:
            item["ts_fmt"] = fmt_ts(item.get("ts") or "")
            item["status_label"] = "UP" if int(item.get("ok") or 0) else "DOWN"
        last = endpoint_summary.get("last") or {}
        if last:
            last["ts_fmt"] = fmt_ts(last.get("ts") or "")
            last["status_label"] = "UP" if int(last.get("ok") or 0) else "DOWN"
            last["status_class"] = "status-ok" if int(last.get("ok") or 0) else "status-fail"
        endpoint_summary["history"] = history
        endpoint_summary["last"] = last or None
        processed.append(endpoint_summary)
    summary["endpoints"] = processed
    summary["configured"] = bool(summary.get("base_url") and honeypot_monitor.endpoints)
    summary["interval_seconds"] = honeypot_monitor.interval
    summary["timeout_seconds"] = honeypot_monitor.timeout
    summary["endpoints_count"] = len(processed)
    return summary


@app.get("/dashboard/honeypot", response_class=HTMLResponse)
def honeypot_availability_page(request: Request, limit: int = 20):
    conn = db()
    try:
        snapshot = _honeypot_snapshot(conn, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    return templates.TemplateResponse(
        "honeypot_availability.html",
        {"request": request, "availability": snapshot, **_license_context()},
    )


@app.get("/admin/health/honeypot")
def honeypot_health(limit: int = 20):
    conn = db()
    try:
        snapshot = _honeypot_snapshot(conn, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    return snapshot


@app.post("/admin/health/honeypot/recheck")
def honeypot_recheck(endpoint: Optional[str] = None):
    if not honeypot_monitor.configured:
        raise HTTPException(status_code=400, detail="HONEYPOT_MONITOR_BASE_URL is not configured")
    try:
        result = honeypot_monitor.run_check(endpoint=endpoint)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"result": result}


@app.get("/admin/health/honeypot/history")
def honeypot_history(endpoint: Optional[str] = None, limit: int = 20):
    target = endpoint or (honeypot_monitor.endpoints[0] if honeypot_monitor.endpoints else None)
    if not target:
        raise HTTPException(status_code=400, detail="endpoint is required")
    conn = db()
    try:
        rows = hp_get_history(conn, endpoint=target, limit=max(1, min(limit, 200)))
    finally:
        conn.close()
    for row in rows:
        row["ts_fmt"] = fmt_ts(row.get("ts") or "")
        row["status_label"] = "UP" if int(row.get("ok") or 0) else "DOWN"
    return {"endpoint": target, "history": rows}


# ensure schema on startup for panel
ensure_schema(db())


def short_id(actor_id: str) -> str:
    return actor_id[:8] + "..." if actor_id and len(actor_id) > 9 else actor_id


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


def fmt_ts(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.isoformat(timespec="seconds")
    except Exception:
        return iso


def _flag_emoji_from_iso2(iso2: str) -> str:
    """Convierte un código ISO2 de país a emoji bandera"""
    if not iso2 or len(iso2) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso2.upper())


def parse_geo_from_extra(extra_json: str):
    """
    Espera algo como:
      {"geo":{"country_iso2":"US","country_name":"United States","flag":"🇺🇸"}, ...}
    """
    try:
        obj = json.loads(extra_json or "{}")
        geo = obj.get("geo") or {}
        iso2 = geo.get("country_iso2") or ""
        flag = geo.get("flag") or _flag_emoji_from_iso2(iso2)
        return {
            "geo_flag": flag,
            "geo_iso2": iso2,
            "geo_name": (geo.get("country_name") or ""),
        }
    except Exception:
        return {"geo_flag": "", "geo_iso2": "", "geo_name": ""}


def _normalize_path(path: str) -> str:
    clean = (path or "/").split("?")[0].strip().lower()
    return clean or "/"


def _path_ngrams(paths):
    grams = []
    if not paths:
        return grams
    for n in (3, 2):
        if len(paths) >= n:
            for i in range(len(paths) - n + 1):
                grams.append(" > ".join(paths[i : i + n]))
    if not grams:
        grams = paths[:]
    return grams[:20]


def _timing_bucket(deltas):
    if not deltas:
        return "unknown"
    med = median(deltas)
    if med < 1:
        return "burst"
    if med < 5:
        return "steady"
    return "slow"


def _stage_flow(stages):
    if not stages:
        return ""
    cleaned = []
    last = None
    for stage in stages:
        if stage is None:
            continue
        try:
            val = int(stage)
        except Exception:
            continue
        if last is None or val != last:
            cleaned.append(f"S{val}")
            last = val
    if not cleaned:
        return ""
    return "-".join(cleaned[:15])


def _sanitize_stage_flow(value: str) -> str:
    if not value:
        return ""
    if any(ch.isdigit() for ch in value):
        return value
    return ""


def _normalize_case_status(value: str) -> str:
    val = (value or "").strip().lower()
    if val in {"open", "monitoring", "closed", "false_positive"}:
        return val
    return "open"


def _safe_json_loads(raw: str, default):
    try:
        data = json.loads(raw or "")
        return data if data is not None else default
    except Exception:
        return default


def _case_actor_ids(cur: sqlite3.Cursor, case_id: int) -> list[str]:
    cur.execute("SELECT actor_id FROM case_actors WHERE case_id=?", (case_id,))
    return [r[0] for r in cur.fetchall()]


def _case_session_steps(cur: sqlite3.Cursor, actor_ids: list[str], limit: int = 300) -> list[dict]:
    if not actor_ids:
        return []
    placeholders = ",".join("?" for _ in actor_ids)
    cur.execute(
        f"""
        SELECT ss.id, ss.session_id, ss.seq, ss.ts, ss.method, ss.path, ss.headers_json,
               ss.body_json, ss.response_status, ss.stage_before, ss.stage_after,
               s.actor_id
        FROM session_steps ss
        JOIN sessions s ON s.session_id = ss.session_id
        WHERE s.actor_id IN ({placeholders})
        ORDER BY ss.ts DESC
        LIMIT ?
        """,
        (*actor_ids, limit),
    )
    return [dict(r) for r in cur.fetchall()]


def _case_events(cur: sqlite3.Cursor, actor_ids: list[str], limit: int = 300) -> list[dict]:
    if not actor_ids:
        return []
    placeholders = ",".join("?" for _ in actor_ids)
    cur.execute(
        f"""
        SELECT id, ts, actor_id, kind, path, method, ip, ua, status, extra_json
        FROM events
        WHERE actor_id IN ({placeholders})
        ORDER BY ts DESC
        LIMIT ?
        """,
        (*actor_ids, limit),
    )
    return [dict(r) for r in cur.fetchall()]


def _case_endpoints_summary(steps: list[dict], events: list[dict], top_k: int = 10) -> dict:
    counter = Counter()
    for row in steps:
        path = _normalize_path(row.get("path") or "/")
        counter[path] += 1
    for row in events:
        path = _normalize_path(row.get("path") or "/")
        counter[path] += 1
    return {"top_paths": [p for p, _ in counter.most_common(top_k)], "counts": counter}


def _case_stage_progression(steps: list[dict]) -> dict:
    seq = []
    counts = Counter()
    for row in steps:
        stage = row.get("stage_after")
        if stage is None:
            stage = row.get("stage_before")
        if stage is None:
            continue
        try:
            val = int(stage)
        except Exception:
            continue
        seq.append(val)
        counts[val] += 1
    flow = _stage_flow(seq)
    return {
        "flow": flow,
        "counts": [{"stage": f"S{k}", "count": int(v)} for k, v in sorted(counts.items())],
        "max_stage": max(counts.keys()) if counts else 0,
    }


def _case_timeline(steps: list[dict], events: list[dict], limit: int = 200) -> list[dict]:
    items = []
    for row in steps:
        items.append(
            {
                "ts": row.get("ts"),
                "type": "step",
                "actor_id": row.get("actor_id"),
                "method": row.get("method"),
                "path": row.get("path"),
                "status": row.get("response_status"),
                "stage": row.get("stage_after") if row.get("stage_after") is not None else row.get("stage_before"),
                "session_id": row.get("session_id"),
                "seq": row.get("seq"),
            }
        )
    for row in events:
        items.append(
            {
                "ts": row.get("ts"),
                "type": "event",
                "actor_id": row.get("actor_id"),
                "method": row.get("method"),
                "path": row.get("path"),
                "status": row.get("status"),
                "kind": row.get("kind"),
            }
        )
    items = [i for i in items if i.get("ts")]
    items.sort(key=lambda x: x.get("ts") or "", reverse=True)
    return items[:limit]


def _case_techniques(steps: list[dict], events: list[dict]) -> list[str]:
    paths = []
    statuses = []
    kinds = []
    for row in steps:
        paths.append(_normalize_path(row.get("path") or "/"))
        status = row.get("response_status")
        if status is not None:
            statuses.append(int(status))
    for row in events:
        paths.append(_normalize_path(row.get("path") or "/"))
        if row.get("status") is not None:
            statuses.append(int(row.get("status")))
        if row.get("kind"):
            kinds.append(str(row.get("kind")))

    techniques = set()
    if any(p in {"/docs", "/openapi.json", "/swagger", "/redoc", "/.env", "/config.json", "/.well-known/security.txt"} for p in paths):
        techniques.add("enumeration")
    if sum(1 for p in paths if "auth/login" in p or p.endswith("/v1/auth/token")) >= 3:
        if any(s >= 401 for s in statuses):
            techniques.add("brute_force")
    if any(p.startswith("/apikeys") or p.startswith("/v1/keys") or p.startswith("/internal/config") for p in paths):
        techniques.add("token_abuse")
    if any(p.startswith("/admin") or p.startswith("/internal") for p in paths):
        techniques.add("privilege_escalation")
    if any(p.startswith("/root") or p.startswith("/console/exec") for p in paths):
        techniques.add("privileged_access")
    if any(p.startswith("/backup") or p.startswith("/api/v1/reports") or p.startswith("/api/v1/transactions") for p in paths):
        techniques.add("data_exfiltration")
    if any(p.startswith("/files") or p in {"/import", "/plugins/install", "/themes/upload"} for p in paths):
        techniques.add("malware_upload")
    if any("token_used" in k or "unknown_token" in k for k in kinds):
        techniques.add("token_probe")
    return sorted(techniques)


def _case_risk_score(stage_max: int, techniques: list[str], endpoint_count: int) -> int:
    score = 0
    score += int(stage_max) * 8
    score += min(30, endpoint_count * 2)
    score += len(techniques) * 6
    return min(100, score)


def _case_similarity(cur: sqlite3.Cursor, case_id: int, endpoints_set: set[str], actor_ids: list[str], limit: int = 3) -> list[dict]:
    cur.execute("SELECT id FROM cases WHERE id != ? ORDER BY updated_at DESC LIMIT 50", (case_id,))
    other_ids = [r[0] for r in cur.fetchall()]
    if not other_ids or not endpoints_set:
        return []
    results = []
    for other_id in other_ids:
        other_actor_ids = _case_actor_ids(cur, other_id)
        shared_actors = set(actor_ids) & set(other_actor_ids)
        other_events = _case_events(cur, other_actor_ids, limit=150)
        other_steps = _case_session_steps(cur, other_actor_ids, limit=150)
        other_endpoints = set(_case_endpoints_summary(other_steps, other_events, top_k=50)["top_paths"])
        if not other_endpoints:
            continue
        inter = endpoints_set & other_endpoints
        union = endpoints_set | other_endpoints
        jaccard = len(inter) / len(union) if union else 0.0
        score = (0.7 * jaccard) + (0.3 if shared_actors else 0.0)
        if score < 0.2:
            continue
        results.append(
            {
                "case_id": other_id,
                "score": round(score, 3),
                "shared_actors": len(shared_actors),
                "shared_paths": sorted(list(inter))[:5],
            }
        )
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:limit]


def _campaign_metrics(cur: sqlite3.Cursor, actor_ids: list[str]) -> dict:
    steps = _case_session_steps(cur, actor_ids, limit=800)
    events = _case_events(cur, actor_ids, limit=800)
    endpoints_summary = _case_endpoints_summary(steps, events, top_k=12)
    stage_info = _case_stage_progression(steps)
    techniques = _case_techniques(steps, events)

    ts_values = []
    for row in events:
        ts = _parse_iso(row.get("ts") or "")
        if ts:
            ts_values.append(ts)
    for row in steps:
        ts = _parse_iso(row.get("ts") or "")
        if ts:
            ts_values.append(ts)
    ts_values.sort()
    first_seen = ts_values[0].isoformat(timespec="seconds").replace("+00:00", "Z") if ts_values else None
    last_seen = ts_values[-1].isoformat(timespec="seconds").replace("+00:00", "Z") if ts_values else None

    # Activity by day/week
    day_counts = Counter()
    week_counts = Counter()
    for ts in ts_values:
        day = ts.strftime("%Y-%m-%d")
        week = ts.strftime("%Y-W%U")
        day_counts[day] += 1
        week_counts[week] += 1

    # Peaks and pauses
    counts = list(day_counts.values())
    peak_days = []
    pause_days = 0
    if counts:
        med = median(counts)
        peak_days = [d for d, c in day_counts.items() if c >= max(3, med * 2)]
        day_list = sorted(day_counts.keys())
        if len(day_list) >= 2:
            gaps = []
            for i in range(1, len(day_list)):
                prev = datetime.fromisoformat(day_list[i - 1])
                curr = datetime.fromisoformat(day_list[i])
                gaps.append((curr - prev).days)
            pause_days = max(gaps) if gaps else 0

    duration_days = 0
    if ts_values:
        duration_days = max(1, (ts_values[-1] - ts_values[0]).days + 1)

    score_det = _case_risk_score(stage_info.get("max_stage") or 0, techniques, len(endpoints_summary.get("top_paths") or []))
    score_det = min(100, score_det + min(20, duration_days * 2) + min(20, len(actor_ids) * 3))

    return {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "activity": {
            "by_day": [{"day": d, "count": c} for d, c in sorted(day_counts.items())],
            "by_week": [{"week": w, "count": c} for w, c in sorted(week_counts.items())],
        },
        "timeline": {
            "peaks": peak_days[:10],
            "max_pause_days": pause_days,
            "duration_days": duration_days,
        },
        "stage": stage_info,
        "techniques": techniques,
        "endpoints": endpoints_summary.get("top_paths") or [],
        "score_det": score_det,
    }


def _campaign_jobs_table_exists(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("SELECT 1 FROM campaign_jobs LIMIT 1")
        return True
    except sqlite3.Error:
        return False


def _serialize_campaign_job(row: Optional[sqlite3.Row]) -> dict:
    if not row:
        return {}
    job = dict(row)
    try:
        job["params"] = json.loads(job.get("params_json") or "{}")
    except Exception:
        job["params"] = {}
    return job


def _compute_campaigns(conn: sqlite3.Connection, config: dict) -> dict:
    t0 = time.perf_counter()
    features_cached = 0
    features_built = 0
    links_created = 0
    cur = conn.cursor()
    cur.execute("DELETE FROM campaign_actor_links")
    cur.execute("DELETE FROM campaigns")

    cache_enabled = True
    # actor_fingerprints may not exist on older DBs
    try:
        cur.execute("SELECT 1 FROM actor_fingerprints LIMIT 1")
    except sqlite3.Error:
        cache_enabled = False

    cur.execute(
        "SELECT actor_id, last_seen FROM actors ORDER BY last_seen DESC LIMIT ?",
        (config["actor_limit"],),
    )
    actor_rows = [dict(r) for r in cur.fetchall()]
    actors = [r["actor_id"] for r in actor_rows]

    actor_features = {}
    actor_meta = {}

    for row in actor_rows:
        actor = row["actor_id"]
        last_seen = row.get("last_seen") or ""

        if cache_enabled:
            cache_row = cur.execute(
                "SELECT fp_json, updated_at FROM actor_fingerprints WHERE actor_id=?",
                (actor,),
            ).fetchone()
            if cache_row and cache_row["fp_json"]:
                try:
                    cache_obj = json.loads(cache_row["fp_json"] or "{}")
                    cache_cfg = cache_obj.get("config") or {}
                    if cache_cfg == config and _is_cache_fresh(cache_row["updated_at"], last_seen):
                        features = set(cache_obj.get("features") or [])
                        meta = cache_obj.get("meta") or {}
                        actor_features[actor] = features
                        actor_meta[actor] = {
                            "top_paths": meta.get("top_paths") or [],
                            "stage_flow": meta.get("stage_flow") or "",
                            "stage_counts": meta.get("stage_counts") or [],
                            "timing": meta.get("timing") or "unknown",
                            "errors": meta.get("errors") or [],
                            "ua": meta.get("ua") or "",
                            "representative_session_id": meta.get("representative_session_id"),
                        }
                        features_cached += 1
                        continue
                except Exception:
                    pass

        features_built += 1
        features = set()
        path_counter = Counter()
        path_single_counter = Counter()
        timing_counter = Counter()
        error_counter = Counter()
        rep_session_id = None
        stage_value_counter = Counter()
        stage_sequence = []

        cur.execute(
            "SELECT session_id FROM sessions WHERE actor_id=? ORDER BY started_at DESC LIMIT ?",
            (actor, config["max_sessions"]),
        )
        session_rows = [dict(r) for r in cur.fetchall()]
        for sess_row in session_rows:
            session_id = sess_row["session_id"]
            if not rep_session_id:
                rep_session_id = session_id
            cur.execute(
                "SELECT seq, ts, path, stage_after, stage_before, response_status FROM session_steps WHERE session_id=? ORDER BY seq ASC",
                (session_id,),
            )
            step_rows = [dict(r) for r in cur.fetchall()]
            if not step_rows:
                continue
            paths = [_normalize_path(step.get("path")) for step in step_rows]
            for path in paths:
                path_single_counter[path] += 1
            ngrams = _path_ngrams(paths)
            for gram in ngrams:
                path_counter[gram] += 1

            stages = []
            for step in step_rows:
                stage_val = step.get("stage_after")
                if stage_val is None:
                    stage_val = step.get("stage_before")
                if stage_val is None:
                    continue
                try:
                    stage_int = int(stage_val)
                except Exception:
                    continue
                stages.append(stage_int)
                stage_value_counter[stage_int] += 1
                stage_sequence.append(stage_int)
            stage_flow = _stage_flow(stages)

            ts_values = [_parse_step_ts(step.get("ts")) for step in step_rows]
            deltas = []
            for i in range(1, len(ts_values)):
                if ts_values[i] and ts_values[i - 1]:
                    deltas.append(abs((ts_values[i] - ts_values[i - 1]).total_seconds()))
            bucket = _timing_bucket(deltas)
            features.add(f"time::{bucket}")
            timing_counter[bucket] += 1

            for step in step_rows:
                status = step.get("response_status")
                if isinstance(status, int) and status >= 400:
                    code = str(status)
                    features.add(f"err::{code}")
                    error_counter[code] += 1

        stage_flow_overall = _stage_flow(stage_sequence)
        if stage_flow_overall:
            features.add(f"stage::{stage_flow_overall}")

        stage_counts = [
            {"stage": f"S{stage}", "count": int(count)}
            for stage, count in sorted(stage_value_counter.items())
        ]

        for gram, _ in path_counter.most_common(config["path_ngram_top_k"]):
            features.add(f"path::{gram}")
        for path, _ in path_single_counter.most_common(config["path_top_k"]):
            features.add(f"path::{path}")

        if not features:
            cur.execute(
                "SELECT path FROM events WHERE actor_id=? AND path IS NOT NULL ORDER BY id DESC LIMIT 100",
                (actor,),
            )
            fallback_paths = [_normalize_path(r[0]) for r in cur.fetchall()]
            for path in fallback_paths:
                path_single_counter[path] += 1
            for gram, _ in Counter(_path_ngrams(fallback_paths)).most_common(config["path_ngram_top_k"]):
                features.add(f"path::{gram}")
            for path, _ in path_single_counter.most_common(config["path_top_k"]):
                features.add(f"path::{path}")

        cur.execute("SELECT ua FROM events WHERE actor_id=? AND ua IS NOT NULL AND ua != '' ORDER BY id DESC LIMIT 1", (actor,))
        ua_row = cur.fetchone()
        ua_value = ""
        if ua_row and ua_row[0]:
            ua_value = ua_row[0].strip()

        actor_features[actor] = features
        actor_meta[actor] = {
            "top_paths": [p for p, _ in path_single_counter.most_common(3)] or [p for p, _ in path_counter.most_common(3)],
            "stage_flow": stage_flow_overall or "",
            "stage_counts": stage_counts,
            "timing": timing_counter.most_common(1)[0][0] if timing_counter else "unknown",
            "errors": [code for code, _ in error_counter.most_common(3)],
            "ua": ua_value,
            "representative_session_id": rep_session_id,
        }
        if cache_enabled:
            cache_payload = {
                "features": list(features),
                "meta": actor_meta[actor],
                "config": config,
            }
            cur.execute(
                "INSERT OR REPLACE INTO actor_fingerprints(actor_id, fp_json, updated_at) VALUES(?,?,?)",
                (actor, json.dumps(cache_payload, ensure_ascii=False), last_seen or _utc_now_iso()),
            )

    campaigns_created = []
    processed = set()
    for actor in actors:
        if actor in processed:
            continue
        fp = actor_features.get(actor, set())
        if len(fp) < config["min_features"]:
            processed.add(actor)
            continue
        group = [actor]
        link_scores = {actor: 1.0}
        overlap_details = {actor: fp}
        for other in actors:
            if other == actor or other in processed:
                continue
            other_fp = actor_features.get(other, set())
            if len(other_fp) < config["min_features"]:
                continue
            inter_features = fp & other_fp
            if len(inter_features) < config["min_intersection"]:
                continue
            union = len(fp | other_fp)
            if union == 0:
                continue
            score = len(inter_features) / union
            if score >= config["min_jaccard"]:
                group.append(other)
                link_scores[other] = round(score, 3)
                overlap_details[other] = inter_features
        for g in group:
            processed.add(g)
        if len(group) >= 2:
            import secrets

            cid = secrets.token_hex(8)
            now = _utc_now_iso()
            seed_meta = actor_meta.get(actor, {})
            rep_session_id = seed_meta.get("representative_session_id")
            label_stage = seed_meta.get("stage_flow") or "replay flow"
            label = f"{len(group)} actors - {label_stage}"
            summary = {
                "seed_actor": actor,
                "group_size": len(group),
                "min_jaccard": config["min_jaccard"],
                "min_intersection": config["min_intersection"],
                "seed_paths_sample": seed_meta.get("top_paths", []),
                "dominant_paths": seed_meta.get("top_paths", []),
                "stage_flow": seed_meta.get("stage_flow"),
                "stage_counts": seed_meta.get("stage_counts", []),
                "timing": seed_meta.get("timing"),
                "ua": seed_meta.get("ua"),
                "representative_session_id": rep_session_id,
                "params": config,
            }
            metrics = _campaign_metrics(cur, group)
            summary.update(
                {
                    "first_seen": metrics.get("first_seen"),
                    "last_seen": metrics.get("last_seen"),
                    "activity": metrics.get("activity"),
                    "timeline": metrics.get("timeline"),
                    "stage": metrics.get("stage"),
                    "techniques": metrics.get("techniques"),
                    "endpoints": metrics.get("endpoints"),
                    "score_det": metrics.get("score_det"),
                }
            )
            cur.execute(
                """
                INSERT OR REPLACE INTO campaigns(
                    campaign_id, label, created_at, last_seen_at, score_avg, features_summary_json,
                    representative_session_id, first_seen_at, score_det, activity_json, timeline_json,
                    stage_flow_json, techniques_json, endpoints_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    cid,
                    label,
                    now,
                    metrics.get("last_seen") or now,
                    0.0,
                    json.dumps(summary, ensure_ascii=False),
                    rep_session_id,
                    metrics.get("first_seen"),
                    int(metrics.get("score_det") or 0),
                    json.dumps(metrics.get("activity") or {}, ensure_ascii=False),
                    json.dumps(metrics.get("timeline") or {}, ensure_ascii=False),
                    json.dumps(metrics.get("stage") or {}, ensure_ascii=False),
                    json.dumps(metrics.get("techniques") or [], ensure_ascii=False),
                    json.dumps(metrics.get("endpoints") or [], ensure_ascii=False),
                ),
            )
            for a in group:
                conf = link_scores.get(a, 0.0)
                overlaps = overlap_details.get(a, set())
                shared_paths = [f.split("path::", 1)[1] for f in overlaps if f.startswith("path::")][:5]
                shared_stage = next((f.split("stage::", 1)[1] for f in overlaps if f.startswith("stage::")), "")
                shared_timing = next((f.split("time::", 1)[1] for f in overlaps if f.startswith("time::")), "")
                shared_errors = [f.split("err::", 1)[1] for f in overlaps if f.startswith("err::")][:5]
                seed_ua = (actor_meta.get(actor, {}) or {}).get("ua") or ""
                member_ua = (actor_meta.get(a, {}) or {}).get("ua") or ""
                shared_ua = member_ua if seed_ua and member_ua and seed_ua == member_ua else ""
                stage_counts = (actor_meta.get(a, {}) or {}).get("stage_counts", [])
                reasons = {
                    "jaccard_vs_seed": conf,
                    "overlap_count": len(overlaps),
                    "shared_paths": shared_paths,
                    "shared_stage_flow": shared_stage,
                    "shared_timing": shared_timing,
                    "shared_errors": shared_errors,
                    "shared_ua": shared_ua,
                    "stage_counts": stage_counts,
                }
                cur.execute(
                    "INSERT OR REPLACE INTO campaign_actor_links(campaign_id, actor_id, confidence, reasons_json, linked_at) VALUES(?,?,?,?,?)",
                    (cid, a, conf, json.dumps(reasons, ensure_ascii=False), now),
                )
                links_created += 1
            campaigns_created.append({"campaign_id": cid, "members": group})

    conn.commit()
    duration_ms = int((time.perf_counter() - t0) * 1000.0)
    return {
        "created": campaigns_created,
        "actors_considered": len(actors),
        "features_cached": features_cached,
        "features_built": features_built,
        "links_created": links_created,
        "duration_ms": duration_ms,
        "params": config,
        "cache_enabled": cache_enabled,
    }


def _run_campaign_job(job_id: str, config: dict) -> None:
    with CAMPAIGN_JOB_LOCK:
        conn = db()
        try:
            campaigns_pro.ensure_campaign_pro_state_table(conn)
            cur = conn.cursor()
            started_at = _utc_now_iso()
            cur.execute(
                "UPDATE campaign_jobs SET status=?, started_at=? WHERE job_id=?",
                ("running", started_at, job_id),
            )
            conn.commit()
            metrics = _compute_campaigns(conn, config)
            finished_at = _utc_now_iso()
            cur.execute(
                """
                UPDATE campaign_jobs
                SET status=?, finished_at=?, duration_ms=?, actors_considered=?, features_cached=?, features_built=?,
                    links_created=?, cache_enabled=?, params_json=?
                WHERE job_id=?
                """,
                (
                    "completed",
                    finished_at,
                    metrics.get("duration_ms"),
                    metrics.get("actors_considered"),
                    metrics.get("features_cached"),
                    metrics.get("features_built"),
                    metrics.get("links_created"),
                    1 if metrics.get("cache_enabled") else 0,
                    json.dumps(config, ensure_ascii=False),
                    job_id,
                ),
            )
            conn.commit()
            campaigns_pro.mark_campaign_status(
                conn,
                status=campaigns_pro.PRO_STATUS_VERIFIED,
                reason="",
                job_id=job_id,
            )
        except Exception as exc:
            err = str(exc)
            try:
                cur.execute(
                    "UPDATE campaign_jobs SET status=?, finished_at=?, error=? WHERE job_id=?",
                    ("failed", _utc_now_iso(), err[:500], job_id),
                )
                conn.commit()
                campaigns_pro.clear_campaign_tables(conn)
                campaigns_pro.mark_campaign_status(
                    conn,
                    status=campaigns_pro.PRO_STATUS_UNVERIFIED,
                    reason=err[:180],
                    job_id=job_id,
                )
            except Exception:
                pass
        finally:
            conn.close()


def _parse_step_ts(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


@app.get("/", response_class=HTMLResponse)
def dashboard_root():
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_overview(request: Request):
    conn = db()
    try:
        campaigns_backend_enabled = bool(campaigns_pro.pro_backend_url())
        campaigns_visible = campaigns_pro.can_render_verified_campaigns(
            conn, backend_enabled=campaigns_backend_enabled
        )
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM actors WHERE last_seen >= datetime('now','-1 day')")
        active_24h = int(cur.fetchone()["cnt"] or 0)
        cur.execute("SELECT COUNT(*) AS cnt FROM actors WHERE last_seen >= datetime('now','-7 day')")
        active_7d = int(cur.fetchone()["cnt"] or 0)
        cur.execute("SELECT COUNT(*) AS cnt FROM events")
        events_total = int(cur.fetchone()["cnt"] or 0)
        cur.execute("SELECT COUNT(*) AS cnt FROM cases WHERE status='open'")
        cases_open = int(cur.fetchone()["cnt"] or 0)
        campaigns_active = 0
        if campaigns_visible:
            cur.execute("SELECT COUNT(*) AS cnt FROM campaigns WHERE COALESCE(last_seen_at, created_at) >= datetime('now','-7 day')")
            campaigns_active = int(cur.fetchone()["cnt"] or 0)
        cur.execute("SELECT COALESCE(MAX(stage_max), 0) AS max_stage FROM sessions")
        stage_max = int(cur.fetchone()["max_stage"] or 0)

        cur.execute(
            """
            SELECT substr(ts,1,10) AS day, COUNT(*) AS cnt
            FROM events
            WHERE ts >= datetime('now','-14 day')
            GROUP BY day
            ORDER BY day
            """
        )
        events_by_day = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT substr(first_seen,1,10) AS day, COUNT(*) AS cnt
            FROM actors
            WHERE first_seen >= datetime('now','-14 day')
            GROUP BY day
            ORDER BY day
            """
        )
        actors_new = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT substr(last_seen,1,10) AS day, COUNT(*) AS cnt
            FROM actors
            WHERE last_seen >= datetime('now','-14 day')
              AND substr(first_seen,1,10) < substr(last_seen,1,10)
            GROUP BY day
            ORDER BY day
            """
        )
        actors_recurrent = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT substr(started_at,1,10) AS day, stage_max AS stage, COUNT(*) AS cnt
            FROM sessions
            WHERE started_at >= datetime('now','-14 day')
            GROUP BY day, stage
            ORDER BY day, stage
            """
        )
        stage_progress = [dict(r) for r in cur.fetchall()]

        cur.execute(
            "SELECT id, title, status, severity, created_at FROM cases ORDER BY created_at DESC LIMIT 5"
        )
        cases_recent = [dict(r) for r in cur.fetchall()]

        campaigns_reactivated = []
        if campaigns_visible:
            cur.execute(
                """
                SELECT campaign_id, label, last_seen_at, COALESCE(first_seen_at, created_at) AS first_seen
                FROM campaigns
                WHERE last_seen_at IS NOT NULL
                  AND last_seen_at >= datetime('now','-1 day')
                  AND COALESCE(first_seen_at, created_at) < datetime(last_seen_at,'-1 day')
                ORDER BY last_seen_at DESC
                LIMIT 5
                """
            )
            campaigns_reactivated = [dict(r) for r in cur.fetchall()]

        cur.execute(
            """
            SELECT actor_id, session_id, stage_max, started_at, ended_at,
                   CAST((julianday(ended_at) - julianday(started_at)) * 86400 AS INTEGER) AS duration_s
            FROM sessions
            WHERE stage_max >= 6
              AND ended_at IS NOT NULL
              AND (julianday(ended_at) - julianday(started_at)) * 86400 <= 900
            ORDER BY ended_at DESC
            LIMIT 5
            """
        )
        fast_escalations = [dict(r) for r in cur.fetchall()]

        return templates.TemplateResponse(
            "dashboard_overview.html",
            {
                "request": request,
                "kpi": {
                    "active_24h": active_24h,
                    "active_7d": active_7d,
                    "events_total": events_total,
                    "cases_open": cases_open,
                    "campaigns_active": campaigns_active,
                    "stage_max": stage_max,
                },
                "events_by_day": events_by_day,
                "actors_new": actors_new,
                "actors_recurrent": actors_recurrent,
                "stage_progress": stage_progress,
                "cases_recent": cases_recent,
                "campaigns_reactivated": campaigns_reactivated,
                "fast_escalations": fast_escalations,
                "license_runtime": _license_runtime_snapshot(),
                **_license_context(),
            },
        )
    finally:
        conn.close()


@app.get("/dashboard/api-modular", response_class=HTMLResponse)
def dashboard_api_modular(request: Request):
    modular_visible = _tier_has_feature(licensing.Feature.API_MUTATION)
    analytics_visible = _tier_has_feature(licensing.Feature.ANALYTICS)
    modular_ok, modular_reason = _pro_feature_status(
        licensing.Feature.API_MUTATION,
        action="panel_api_modular",
    )
    analytics_ok, analytics_reason = _pro_feature_status(
        licensing.Feature.ANALYTICS,
        action="panel_pro_analytics",
    )
    return templates.TemplateResponse(
        "api_modular.html",
        {
            "request": request,
            "pro_modular_visible": modular_visible,
            "pro_analytics_visible": analytics_visible,
            "pro_modular_enabled": modular_ok,
            "pro_modular_reason": modular_reason,
            "pro_analytics_enabled": analytics_ok,
            "pro_analytics_reason": analytics_reason,
            **_license_context(),
        },
    )


def _normalize_catalog_method(method: str) -> str:
    raw = str(method or "*").strip().upper()
    return raw or "*"


def _normalize_catalog_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        return "/" + raw
    return raw


def _honeypot_public_endpoint_catalog() -> list[dict]:
    # Import lazily to avoid coupling app startup order.
    try:
        from app.honeypot_public import app as public_api
    except Exception:
        return []

    seen: set[str] = set()
    out: list[dict] = []
    for route in getattr(public_api, "routes", []):
        path = _normalize_catalog_path(getattr(route, "path", "") or "")
        methods = set(getattr(route, "methods", set()) or set())
        if not path or path.startswith("/static/"):
            continue
        for method in sorted(methods):
            mm = _normalize_catalog_method(method)
            if mm in {"HEAD", "OPTIONS"}:
                continue
            key = f"{mm} {path}"
            if key in seen:
                continue
            seen.add(key)
            out.append({"method": mm, "path": path, "label": key})
    out.sort(key=lambda item: (item.get("path") or "", item.get("method") or ""))
    return out


def _is_real_honeypot_endpoint(path: str, method: str, catalog: list[dict]) -> bool:
    target_path = _normalize_catalog_path(path)
    target_method = _normalize_catalog_method(method)
    for item in catalog:
        item_method = _normalize_catalog_method(item.get("method") or "*")
        item_path = _normalize_catalog_path(item.get("path") or "/")
        if target_method != "*" and item_method != target_method:
            continue
        if api_modular.path_matches_pattern(item_path, target_path):
            return True
    return False


def _api_modular_endpoint_catalog(conn: sqlite3.Connection, limit: int = 400) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []

    def _add(method: str, path: str) -> None:
        mm = _normalize_catalog_method(method)
        pp = _normalize_catalog_path(path)
        if pp.startswith("/static/"):
            return
        key = f"{mm} {pp}"
        if key in seen:
            return
        seen.add(key)
        out.append({"method": mm, "path": pp, "label": key})

    real_routes = _honeypot_public_endpoint_catalog()
    # Real honeypot routes only.
    for item in real_routes:
        _add(str(item.get("method") or "*"), str(item.get("path") or "/"))

    rows = conn.execute(
        """
        SELECT method, path
        FROM api_endpoint_configs
        ORDER BY updated_ts DESC
        LIMIT ?
        """,
        (max(1, int(limit)),),
    ).fetchall()
    for row in rows:
        row_method = str(row["method"] or "*")
        row_path = str(row["path"] or "/")
        if _is_real_honeypot_endpoint(row_path, row_method, real_routes):
            _add(row_method, row_path)

    out.sort(key=lambda item: (item.get("path") or "", item.get("method") or ""))
    return out


@app.get("/dashboard/api-modular/state", response_class=JSONResponse)
def dashboard_api_modular_state():
    modular_visible = _tier_has_feature(licensing.Feature.API_MUTATION)
    analytics_visible = _tier_has_feature(licensing.Feature.ANALYTICS)
    modular_ok, modular_reason = _pro_feature_status(
        licensing.Feature.API_MUTATION,
        action="panel_api_modular",
    )
    analytics_ok, analytics_reason = _pro_feature_status(
        licensing.Feature.ANALYTICS,
        action="panel_pro_analytics",
    )
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        configs = api_modular.list_endpoint_configs(conn)
        rules = api_modular.list_rules(conn) if modular_ok else []
        mutation = api_modular.get_mutation_config(conn) if modular_ok else {"mutation_policy": "none", "mutation_intensity": 0}
        endpoint_catalog = _api_modular_endpoint_catalog(conn, limit=600)
    finally:
        conn.close()
    return {
        "templates": api_modular.list_templates(),
        "endpoint_configs": configs,
        "mutation": mutation,
        "rules": rules,
        "endpoint_catalog": endpoint_catalog,
        "pro_modular_visible": modular_visible,
        "pro_modular_enabled": modular_ok,
        "pro_modular_reason": modular_reason,
        "pro_analytics_visible": analytics_visible,
        "pro_analytics_enabled": analytics_ok,
        "pro_analytics_reason": analytics_reason,
    }


@app.post("/dashboard/api-modular/config", response_class=JSONResponse)
def dashboard_api_modular_save_config(payload: dict = Body(default={})):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    path = str(payload.get("path") or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="path_required")
    method = str(payload.get("method") or "*").strip().upper() or "*"
    config_raw = payload.get("config")
    if not isinstance(config_raw, dict):
        raise HTTPException(status_code=400, detail="config_required")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        route_catalog = _honeypot_public_endpoint_catalog()
        if not _is_real_honeypot_endpoint(path, method, route_catalog):
            raise HTTPException(status_code=400, detail="unknown_honeypot_endpoint")
        saved = api_modular.upsert_endpoint_config(conn, path=path, method=method, config=config_raw)
    finally:
        conn.close()
    return {"saved": True, "entry": saved}


@app.post("/dashboard/api-modular/config/delete", response_class=JSONResponse)
def dashboard_api_modular_delete_config(payload: dict = Body(default={})):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    path = str(payload.get("path") or "").strip()
    method = str(payload.get("method") or "*").strip().upper() or "*"
    if not path:
        raise HTTPException(status_code=400, detail="path_required")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        deleted = api_modular.delete_endpoint_config(conn, path=path, method=method)
    finally:
        conn.close()
    return {"deleted": bool(deleted)}


@app.post("/dashboard/api-modular/template/apply", response_class=JSONResponse)
def dashboard_api_modular_apply_template(payload: dict = Body(default={})):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    template_name = str(payload.get("template_name") or "").strip().lower()
    path = str(payload.get("path") or "").strip()
    method = str(payload.get("method") or "*").strip().upper() or "*"
    if not template_name:
        raise HTTPException(status_code=400, detail="template_name_required")
    if not path:
        raise HTTPException(status_code=400, detail="path_required")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        route_catalog = _honeypot_public_endpoint_catalog()
        if not _is_real_honeypot_endpoint(path, method, route_catalog):
            raise HTTPException(status_code=400, detail="unknown_honeypot_endpoint")
        try:
            saved = api_modular.apply_template(conn, template_name=template_name, path=path, method=method)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        conn.close()
    return {"saved": True, "entry": saved}


@app.post("/dashboard/api-modular/mutation", response_class=JSONResponse)
def dashboard_api_modular_set_mutation(payload: dict = Body(default={})):
    if not _has_modular_pro():
        raise HTTPException(status_code=403, detail="feature not available")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    policy = str(payload.get("mutation_policy") or "none")
    intensity = int(payload.get("mutation_intensity") or 0)
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        saved = api_modular.set_mutation_config(conn, mutation_policy=policy, mutation_intensity=intensity)
    finally:
        conn.close()
    return {"saved": True, "mutation": saved}


@app.post("/dashboard/api-modular/rules", response_class=JSONResponse)
def dashboard_api_modular_add_rule(payload: dict = Body(default={})):
    if not _has_modular_pro():
        raise HTTPException(status_code=403, detail="feature not available")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        saved = api_modular.add_rule(conn, payload)
    finally:
        conn.close()
    return {"saved": True, "rule": saved}


@app.post("/dashboard/api-modular/rules/delete", response_class=JSONResponse)
def dashboard_api_modular_delete_rule(payload: dict = Body(default={})):
    if not _has_modular_pro():
        raise HTTPException(status_code=403, detail="feature not available")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")
    rule_id = int(payload.get("id") or 0)
    if rule_id <= 0:
        raise HTTPException(status_code=400, detail="id_required")
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        deleted = api_modular.delete_rule(conn, rule_id=rule_id)
    finally:
        conn.close()
    return {"deleted": bool(deleted)}


@app.get("/dashboard/api-modular/analytics", response_class=JSONResponse)
def dashboard_api_modular_analytics(hours: int = 24):
    if not _has_analytics_pro():
        raise HTTPException(status_code=403, detail="feature not available")
    window_hours = max(1, min(int(hours), 168))
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        endpoints = api_modular.analytics_endpoint_metrics(conn, window_hours=window_hours, limit=20)
        interest = api_modular.analytics_interest_scoring(conn, window_hours=window_hours, limit=20)
        fingerprinting = api_modular.analytics_fingerprinting(conn, window_hours=window_hours, limit=20)
    finally:
        conn.close()
    return {
        "window_hours": window_hours,
        "endpoints": endpoints,
        "interest": interest,
        "fingerprinting": fingerprinting,
    }


@app.get("/dashboard/actors", response_class=HTMLResponse)
def dashboard(request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            WITH last_events AS (
              SELECT e.*
              FROM events e
              JOIN (
                SELECT actor_id, MAX(id) AS max_id
                FROM events
                GROUP BY actor_id
              ) m ON e.actor_id = m.actor_id AND e.id = m.max_id
            )
            SELECT
              a.actor_id, a.first_seen, a.last_seen, a.score,
              a.err_total, a.err_consecutive, a.last_status, a.last_error_ts,
              le.ip AS last_ip,
              le.ua AS last_ua,
              le.extra_json AS last_extra_json,
              (SELECT e.extra_json FROM events e WHERE e.actor_id = a.actor_id AND e.extra_json LIKE '%country_iso2%' ORDER BY e.id DESC LIMIT 1) AS last_geo_extra_json,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind = 'token_used') AS token_used_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind = 'unknown_token') AS unknown_token_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind LIKE 'recon_%') AS recon_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind LIKE 'auth_%') AS auth_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND (e.kind LIKE 'admin_%' OR e.kind LIKE 'internal_%')) AS internal_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND (e.kind LIKE 'devops_%' OR e.kind = 'pipeline_job')) AS devops_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND (e.kind LIKE 'files_%' OR e.kind = 'upload_trap')) AS files_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND (e.kind LIKE 'console_%' OR e.kind LIKE 'root_%')) AS console_count,
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind LIKE 'business_%') AS business_count
            FROM actors a
            LEFT JOIN last_events le ON le.actor_id = a.actor_id
            WHERE COALESCE(a.lifecycle_state, 'active') != 'deleted'
              AND EXISTS (SELECT 1 FROM events e WHERE e.actor_id = a.actor_id)
            ORDER BY a.last_seen DESC
            LIMIT 200
            """
        )
        actors = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COALESCE(MAX(stage_max), 0) AS max_stage FROM sessions")
        max_stage_row = cur.fetchone()
        max_stage = int(max_stage_row["max_stage"] or 0) if max_stage_row else 0

        for a in actors:
            a["short"] = short_id(a["actor_id"])
            a["stage"] = stage_from_score(int(a.get("score") or 0))
            a["last_seen_fmt"] = fmt_ts(a["last_seen"])

            geo = parse_geo_from_extra(a.get("last_extra_json") or "")
            if not geo.get("geo_iso2"):
                geo = parse_geo_from_extra(a.get("last_geo_extra_json") or "")
            a.update(geo)

            # Si no hay flag pero tenemos IP, intentar resolver la geolocalización
            if not a.get("geo_iso2") and a.get("last_ip"):
                try:
                    import geoip2.database
                    if os.path.exists(HP_GEOIP_DB):
                        reader = geoip2.database.Reader(HP_GEOIP_DB)
                        try:
                            resp = reader.country(a["last_ip"])
                            iso = (resp.country.iso_code or "").strip().upper()
                            name = (resp.country.name or "").strip()
                            if iso:
                                a["geo_iso2"] = iso
                                a["geo_name"] = name
                                a["geo_flag"] = _flag_emoji_from_iso2(iso)
                        finally:
                            reader.close()
                except Exception:
                    pass

            a["badges"] = []
            if int(a.get("recon_count") or 0) > 0:
                a["badges"].append("recon")
            if int(a.get("auth_count") or 0) > 0:
                a["badges"].append("auth")
            if int(a.get("internal_count") or 0) > 0:
                a["badges"].append("internal")
            if int(a.get("devops_count") or 0) > 0:
                a["badges"].append("devops")
            if int(a.get("files_count") or 0) > 0:
                a["badges"].append("files")
            if int(a.get("console_count") or 0) > 0:
                a["badges"].append("console")
            if int(a.get("business_count") or 0) > 0:
                a["badges"].append("business")
            if int(a.get("token_used_count") or 0) > 0:
                a["badges"].append(f"token_used?{a['token_used_count']}")
            if int(a.get("unknown_token_count") or 0) > 0:
                a["badges"].append(f"unknown_token?{a['unknown_token_count']}")

            # errores (desde tabla actors)
            err_total = int(a.get("err_total") or 0)
            err_consec = int(a.get("err_consecutive") or 0)
            a["err_total"] = err_total
            a["err_consecutive"] = err_consec
            a["err_badge"] = f"err×{err_total}" if err_total > 0 else ""

        return templates.TemplateResponse(
            "dashboard.html",
            {"request": request, "actors": actors, "max_stage": max_stage, **_license_context()},
        )
    finally:
        conn.close()


# -------- Dashboard management endpoints: Cases / Sessions / Campaigns --------
@app.get("/dashboard/cases", response_class=HTMLResponse)
def dashboard_cases(request: Request):
    _require_feature(licensing.Feature.CASES)
    conn = db()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT id, title, severity, status, created_at, updated_at FROM cases ORDER BY updated_at DESC LIMIT 200")
        cases = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse(
            "cases.html", {"request": request, "cases": cases, **_license_context()}
        )
    finally:
        conn.close()


@app.get("/dashboard/cases/{case_id}", response_class=HTMLResponse)
def dashboard_case_detail(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM cases WHERE id=?", (case_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404)
        case = dict(row)
        case["status"] = _normalize_case_status(case.get("status"))
        cur.execute("SELECT actor_id, role, added_at FROM case_actors WHERE case_id=?", (case_id,))
        actors = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT id, ref_type, ref_id, note, added_at FROM case_evidence WHERE case_id=? ORDER BY added_at DESC", (case_id,))
        evidence_rows = [dict(r) for r in cur.fetchall()]

        # Campaigns list for linking
        cur.execute("SELECT campaign_id, label FROM campaigns ORDER BY last_seen_at DESC LIMIT 200")
        campaigns = [dict(r) for r in cur.fetchall()]

        # Build case intelligence snapshot
        actor_ids = [a["actor_id"] for a in actors]
        steps = _case_session_steps(cur, actor_ids, limit=400)
        events = _case_events(cur, actor_ids, limit=400)
        endpoints_summary = _case_endpoints_summary(steps, events, top_k=12)
        stage_info = _case_stage_progression(steps)
        techniques = _case_techniques(steps, events)
        risk_score = _case_risk_score(stage_info.get("max_stage") or 0, techniques, len(endpoints_summary.get("top_paths") or []))
        timeline = _case_timeline(steps, events, limit=200)
        endpoints_set = set(endpoints_summary.get("top_paths") or [])
        similarity = _case_similarity(cur, case_id, endpoints_set, actor_ids)

        timeline_start = timeline[-1]["ts"] if timeline else None
        timeline_end = timeline[0]["ts"] if timeline else None

        # Persist a light cache on the case row (best-effort)
        now = _utc_now_iso()
        try:
            cur.execute(
                """
                UPDATE cases
                SET risk_score=?, techniques_json=?, endpoints_json=?, stage_flow_json=?,
                    timeline_start=?, timeline_end=?, similarity_json=?, last_intel_ts=?
                WHERE id=?
                """,
                (
                    int(risk_score),
                    json.dumps(techniques, ensure_ascii=False),
                    json.dumps({"top_paths": endpoints_summary.get("top_paths") or []}, ensure_ascii=False),
                    json.dumps(stage_info, ensure_ascii=False),
                    timeline_start,
                    timeline_end,
                    json.dumps(similarity, ensure_ascii=False),
                    now,
                    case_id,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()

        replay_sessions = []
        replay_steps = []
        for ev in evidence_rows:
            if ev["ref_type"] == "session":
                sess_row = cur.execute(
                    "SELECT session_id, actor_id, started_at, ended_at, stage_max, summary FROM sessions WHERE session_id=?",
                    (ev["ref_id"],),
                ).fetchone()
                if sess_row:
                    sess = dict(sess_row)
                    sess["evidence_id"] = ev["id"]
                    sess["note"] = ev["note"]
                    sess["added_at"] = ev["added_at"]
                    sess["session_id_short"] = sess["session_id"][:8] + "..." if len(sess["session_id"]) > 8 else sess["session_id"]
                    sess["started_fmt"] = fmt_ts(sess.get("started_at") or "")
                    sess["ended_fmt"] = fmt_ts(sess.get("ended_at")) if sess.get("ended_at") else "-"
                    replay_sessions.append(sess)
            elif ev["ref_type"] == "step":
                try:
                    step_lookup_id = int(ev["ref_id"])
                except (TypeError, ValueError):
                    step_lookup_id = None
                if step_lookup_id is not None:
                    step_row = cur.execute(
                        "SELECT id, session_id, seq, ts, method, path, stage_after, response_status, headers_json, body_json, response_json FROM session_steps WHERE id=?",
                        (step_lookup_id,),
                    ).fetchone()
                    if step_row:
                        step = dict(step_row)
                        step["evidence_id"] = ev["id"]
                        step["note"] = ev["note"]
                        step["added_at"] = ev["added_at"]
                        step["ts_fmt"] = fmt_ts(step.get("ts") or "")
                        step["headers_json"] = step.get("headers_json") or ""
                        step["body_json"] = step.get("body_json") or ""
                        step["response_json"] = step.get("response_json") or ""
                        replay_steps.append(step)
        context = {
            "request": request,
            "case": case,
            "actors": actors,
            "replay_sessions": replay_sessions,
            "replay_steps": replay_steps,
            "campaigns": campaigns,
            "case_timeline": timeline,
            "case_endpoints": endpoints_summary.get("top_paths") or [],
            "case_stage": stage_info,
            "case_techniques": techniques,
            "case_risk_score": risk_score,
            "case_similarity": similarity,
        }
        context.update(_license_context())
        return templates.TemplateResponse("case_detail.html", context)
    finally:
        conn.close()


@app.post("/dashboard/cases")
def create_case(request: Request):
    _require_feature(licensing.Feature.CASES)
    title = request.query_params.get("title") or "Untitled"
    description = request.query_params.get("description") or ""
    severity = request.query_params.get("severity") or "low"
    tags = request.query_params.get("tags") or ""
    status = _normalize_case_status(request.query_params.get("status") or "open")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO cases(title, description, severity, tags, created_at, updated_at, status) VALUES(?,?,?,?,?,?,?)", (title, description, severity, tags, now, now, status))
        conn.commit()
        new_id = cur.lastrowid
        return {"id": new_id}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/rename")
def rename_case(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    title = (request.query_params.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="title required")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE cases SET title=?, updated_at=? WHERE id=?", (title, now, case_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="case not found")
        conn.commit()
        return {"ok": True, "title": title}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/status")
def update_case_status(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    status = _normalize_case_status(request.query_params.get("status") or "")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE cases SET status=?, updated_at=? WHERE id=?", (status, now, case_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="case not found")
        conn.commit()
        return {"ok": True, "status": status}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/campaign")
def link_case_campaign(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    campaign_id = (request.query_params.get("campaign_id") or "").strip()
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        if campaign_id:
            cur.execute("SELECT campaign_id FROM campaigns WHERE campaign_id=?", (campaign_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="campaign not found")
            cur.execute("UPDATE cases SET campaign_id=?, updated_at=? WHERE id=?", (campaign_id, now, case_id))
        else:
            cur.execute("UPDATE cases SET campaign_id=NULL, updated_at=? WHERE id=?", (now, case_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="case not found")
        conn.commit()
        return {"ok": True, "campaign_id": campaign_id or None}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/actors")
def add_actor_to_case(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    actor_id = request.query_params.get("actor_id")
    role = request.query_params.get("role") or "related"
    if not actor_id:
        raise HTTPException(status_code=400, detail="actor_id required")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO case_actors(case_id, actor_id, added_at, role) VALUES(?,?,?,?)", (case_id, actor_id, now, role))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/actors/remove")
def remove_actor_from_case(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    actor_id = (request.query_params.get("actor_id") or "").strip()
    if not actor_id:
        raise HTTPException(status_code=400, detail="actor_id required")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM case_actors WHERE case_id=? AND actor_id=?", (case_id, actor_id))
        cur.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/evidence")
def add_case_evidence_entry(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    ref_type = (request.query_params.get("ref_type") or "").strip().lower()
    ref_id = (request.query_params.get("ref_id") or "").strip()
    note = request.query_params.get("note") or ""
    if ref_type not in {"session", "step"}:
        raise HTTPException(status_code=400, detail="ref_type must be 'session' or 'step'")
    if not ref_id:
        raise HTTPException(status_code=400, detail="ref_id required")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM cases WHERE id=?", (case_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="case not found")

        evidence_json = {}
        source_path = None
        source_method = None
        source_stage = None
        source_status = None
        actor_id = None

        if ref_type == "session":
            sess_row = cur.execute(
                "SELECT session_id, actor_id, started_at, ended_at, stage_max, summary FROM sessions WHERE session_id=?",
                (ref_id,),
            ).fetchone()
            if not sess_row:
                raise HTTPException(status_code=404, detail="session not found")
            actor_id = sess_row["actor_id"]
            evidence_json = {
                "session_id": sess_row["session_id"],
                "actor_id": sess_row["actor_id"],
                "started_at": sess_row["started_at"],
                "ended_at": sess_row["ended_at"],
                "stage_max": sess_row["stage_max"],
                "summary": sess_row["summary"],
            }
        else:
            step_row = cur.execute(
                """
                SELECT ss.id, ss.session_id, ss.seq, ss.ts, ss.method, ss.path, ss.headers_json, ss.body_json,
                       ss.response_status, ss.response_json, ss.stage_before, ss.stage_after, s.actor_id
                FROM session_steps ss
                JOIN sessions s ON s.session_id = ss.session_id
                WHERE ss.id=?
                """,
                (ref_id,),
            ).fetchone()
            if not step_row:
                raise HTTPException(status_code=404, detail="step not found")
            actor_id = step_row["actor_id"]
            source_path = step_row["path"]
            source_method = step_row["method"]
            source_stage = step_row["stage_after"] if step_row["stage_after"] is not None else step_row["stage_before"]
            source_status = step_row["response_status"]
            evidence_json = {
                "step_id": step_row["id"],
                "session_id": step_row["session_id"],
                "seq": step_row["seq"],
                "ts": step_row["ts"],
                "method": step_row["method"],
                "path": step_row["path"],
                "headers": _safe_json_loads(step_row["headers_json"], step_row["headers_json"]),
                "body": _safe_json_loads(step_row["body_json"], step_row["body_json"]),
                "response_status": step_row["response_status"],
                "response_json": _safe_json_loads(step_row["response_json"], step_row["response_json"]),
                "stage_before": step_row["stage_before"],
                "stage_after": step_row["stage_after"],
                "actor_id": step_row["actor_id"],
            }

        cur.execute(
            """
            INSERT INTO case_evidence(case_id, ref_type, ref_id, note, added_at, evidence_json, source_path, source_method, source_stage, source_status, actor_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                case_id,
                ref_type,
                str(ref_id),
                note,
                now,
                json.dumps(evidence_json, ensure_ascii=False),
                source_path,
                source_method,
                source_stage,
                source_status,
                actor_id,
            ),
        )
        cur.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/evidence/remove")
def remove_case_evidence_entry(case_id: int, request: Request):
    _require_feature(licensing.Feature.CASES)
    evidence_id = (request.query_params.get("evidence_id") or "").strip()
    if not evidence_id:
        raise HTTPException(status_code=400, detail="evidence_id required")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM case_evidence WHERE case_id=? AND id=?", (case_id, evidence_id))
        cur.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.get("/dashboard/actor_add_case/{actor_id}")
def actor_add_case_ui(actor_id: str, request: Request):
    _require_feature(licensing.Feature.CASES)
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, title, status, severity, updated_at FROM cases WHERE status='open' ORDER BY updated_at DESC")
        cases = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse(
            "actor_add_case_modal.html",
            {"request": request, "actor_id": actor_id, "cases": cases, **_license_context()},
        )
    finally:
        conn.close()


@app.post("/dashboard/cases/quick")
def quick_create_case_and_add_actor(request: Request):
    _require_feature(licensing.Feature.CASES)
    title = request.query_params.get("title") or "Auto Case"
    actor_id = request.query_params.get("actor_id")
    if not actor_id:
        raise HTTPException(status_code=400, detail="actor_id required")
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        # create case
        cur.execute("INSERT INTO cases(title, description, severity, tags, created_at, updated_at) VALUES(?,?,?,?,?,?)", (title, "", "medium", "", now, now))
        conn.commit()
        case_id = cur.lastrowid
        # add actor
        cur.execute("INSERT OR REPLACE INTO case_actors(case_id, actor_id, added_at, role) VALUES(?,?,?,?)", (case_id, actor_id, now, "primary"))
        conn.commit()
        return {"ok": True, "case_id": case_id}
    finally:
        conn.close()


@app.delete("/dashboard/cases/{case_id}")
def delete_case(case_id: int):
    _require_feature(licensing.Feature.CASES)
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM case_actors WHERE case_id=?", (case_id,))
        cur.execute("DELETE FROM case_evidence WHERE case_id=?", (case_id,))
        deleted = cur.execute("DELETE FROM cases WHERE id=?", (case_id,)).rowcount
        if deleted == 0:
            conn.rollback()
            raise HTTPException(status_code=404, detail="case not found")
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


def _case_export_payload(cur: sqlite3.Cursor, case_id: int) -> dict:
    cur.execute("SELECT * FROM cases WHERE id=?", (case_id,))
    case_row = cur.fetchone()
    if not case_row:
        raise HTTPException(status_code=404, detail="case not found")
    case = dict(case_row)
    case["status"] = _normalize_case_status(case.get("status"))
    cur.execute("SELECT actor_id, role, added_at FROM case_actors WHERE case_id=?", (case_id,))
    actors = [dict(r) for r in cur.fetchall()]
    actor_ids = [a["actor_id"] for a in actors]
    steps = _case_session_steps(cur, actor_ids, limit=500)
    events = _case_events(cur, actor_ids, limit=500)
    endpoints_summary = _case_endpoints_summary(steps, events, top_k=20)
    stage_info = _case_stage_progression(steps)
    techniques = _case_techniques(steps, events)
    risk_score = _case_risk_score(stage_info.get("max_stage") or 0, techniques, len(endpoints_summary.get("top_paths") or []))
    timeline = _case_timeline(steps, events, limit=300)
    similarity = _case_similarity(cur, case_id, set(endpoints_summary.get("top_paths") or []), actor_ids, limit=5)

    cur.execute(
        "SELECT id, ref_type, ref_id, note, added_at, evidence_json, source_path, source_method, source_stage, source_status, actor_id FROM case_evidence WHERE case_id=? ORDER BY added_at DESC",
        (case_id,),
    )
    evidences = [dict(r) for r in cur.fetchall()]
    for ev in evidences:
        ev["evidence_json"] = _safe_json_loads(ev.get("evidence_json"), ev.get("evidence_json"))

    payload = {
        "case": case,
        "actors": actors,
        "campaign_id": case.get("campaign_id"),
        "timeline": timeline,
        "endpoints": endpoints_summary.get("top_paths") or [],
        "stage_progression": stage_info,
        "techniques": techniques,
        "risk_score": risk_score,
        "similar_cases": similarity,
        "evidence": evidences,
    }
    return payload


def _case_export_markdown(payload: dict) -> str:
    case = payload.get("case") or {}
    lines = [
        f"# Case #{case.get('id')} — {case.get('title')}",
        "",
        f"Status: **{case.get('status')}**",
        f"Severity: **{case.get('severity') or 'n/a'}**",
        f"Campaign: `{payload.get('campaign_id') or '-'}`",
        f"Created: {case.get('created_at')}",
        f"Updated: {case.get('updated_at')}",
        "",
        "## Summary",
        f"- Risk score: **{payload.get('risk_score')}**",
        f"- Techniques: {', '.join(payload.get('techniques') or []) or '-'}",
        f"- Top endpoints: {', '.join(payload.get('endpoints') or []) or '-'}",
        "",
        "## Actors",
    ]
    for a in payload.get("actors") or []:
        lines.append(f"- `{a.get('actor_id')}` ({a.get('role') or 'related'})")

    lines += ["", "## Timeline (recent)"]
    for item in payload.get("timeline") or []:
        ts = item.get("ts")
        if item.get("type") == "step":
            lines.append(f"- {ts} {item.get('method') or ''} {item.get('path') or ''} stage={item.get('stage')} status={item.get('status')}")
        else:
            lines.append(f"- {ts} {item.get('kind') or 'event'} {item.get('path') or ''} status={item.get('status')}")

    lines += ["", "## Evidence"]
    for ev in payload.get("evidence") or []:
        lines.append(f"- [{ev.get('ref_type')}] {ev.get('ref_id')} — {ev.get('note') or ''}")

    if payload.get("similar_cases"):
        lines += ["", "## Similar Cases"]
        for sc in payload.get("similar_cases"):
            lines.append(f"- Case #{sc.get('case_id')} (score {sc.get('score')}, shared actors {sc.get('shared_actors')})")

    return "\n".join(lines).strip() + "\n"


@app.get("/dashboard/cases/{case_id}/export.json")
def export_case_json(case_id: int):
    _require_feature(licensing.Feature.CASES)
    conn = db()
    try:
        cur = conn.cursor()
        payload = _case_export_payload(cur, case_id)
        return JSONResponse(payload)
    finally:
        conn.close()


@app.get("/dashboard/cases/{case_id}/export.md", response_class=PlainTextResponse)
def export_case_markdown(case_id: int):
    _require_feature(licensing.Feature.CASES)
    conn = db()
    try:
        cur = conn.cursor()
        payload = _case_export_payload(cur, case_id)
        return PlainTextResponse(_case_export_markdown(payload))
    finally:
        conn.close()



@app.post("/dashboard/actors/{actor_id}/archive")
def archive_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET is_archived=1 WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/unarchive")
def unarchive_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET is_archived=0 WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/trash")
def trash_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET lifecycle_state='deleted' WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/restore")
def restore_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE actors SET lifecycle_state='active' WHERE actor_id=?", (actor_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/{actor_id}/purge")
def purge_actor(actor_id: str):
    conn = db()
    try:
        cur = conn.cursor()
        _purge_actor_data(cur, actor_id)
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/actors/purge_bulk")
async def purge_actors_bulk(request: Request):
    data = None
    try:
        data = await request.json()
    except Exception:
        data = None
    actor_ids: List[str] = []
    try:
        payload = data if isinstance(data, dict) else {}
    except Exception:
        payload = {}
    if payload:
        actor_ids = payload.get("actor_ids") or []
    if not actor_ids:
        raw = (request.query_params.get("actor_ids") or "").strip()
        if raw:
            actor_ids = [a.strip() for a in raw.split(",") if a.strip()]
    if not actor_ids:
        raise HTTPException(status_code=400, detail="actor_ids required")

    conn = db()
    try:
        cur = conn.cursor()
        for actor_id in actor_ids:
            _purge_actor_data(cur, actor_id)
        conn.commit()
        return {"ok": True, "count": len(actor_ids)}
    finally:
        conn.close()


def _purge_actor_data(cur: sqlite3.Cursor, actor_id: str) -> None:
    # remove case evidence tied to this actor's sessions/steps or direct actor evidence
    cur.execute("DELETE FROM case_evidence WHERE ref_type='actor' AND ref_id=?", (actor_id,))
    cur.execute("DELETE FROM case_evidence WHERE actor_id=?", (actor_id,))
    cur.execute("SELECT session_id FROM sessions WHERE actor_id=?", (actor_id,))
    session_ids = [r[0] for r in cur.fetchall()]
    if session_ids:
        cur.execute(
            "DELETE FROM case_evidence WHERE ref_type='session' AND ref_id IN ({})".format(
                ",".join("?" for _ in session_ids)
            ),
            session_ids,
        )
        cur.execute(
            """
            DELETE FROM case_evidence
            WHERE ref_type='step' AND ref_id IN (
                SELECT CAST(id AS TEXT) FROM session_steps
                WHERE session_id IN ({})
            )
            """.format(",".join("?" for _ in session_ids)),
            session_ids,
        )
        cur.execute(
            "DELETE FROM session_steps WHERE session_id IN ({})".format(",".join("?" for _ in session_ids)),
            session_ids,
        )
        cur.execute(
            "DELETE FROM sessions WHERE session_id IN ({})".format(",".join("?" for _ in session_ids)),
            session_ids,
        )

    cur.execute("DELETE FROM case_actors WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM tokens WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM issued_secrets WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM events WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM campaign_actor_links WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM actor_fingerprints WHERE actor_id=?", (actor_id,))
    cur.execute("DELETE FROM actors WHERE actor_id=?", (actor_id,))


@app.get("/dashboard/actors/deleted", response_class=HTMLResponse)
def deleted_actors(request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT actor_id, first_seen, last_seen, score
            FROM actors
            WHERE COALESCE(lifecycle_state, 'active') = 'deleted'
            ORDER BY last_seen DESC
            LIMIT 500
            """
        )
        rows = [dict(r) for r in cur.fetchall()]
        for a in rows:
            a["short"] = short_id(a["actor_id"])
            a["stage"] = stage_from_score(int(a.get("score") or 0))
            a["last_seen_fmt"] = fmt_ts(a["last_seen"])
            a["first_seen_fmt"] = fmt_ts(a["first_seen"])
        return templates.TemplateResponse(
            "actors_deleted.html", {"request": request, "actors": rows, **_license_context()}
        )
    finally:
        conn.close()


@app.get("/dashboard/actors/{actor_id}/sessions", response_class=HTMLResponse)
def actor_sessions(actor_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT actor_id, last_seen, score FROM actors WHERE actor_id=?", (actor_id,))
        actor_row = cur.fetchone()
        if not actor_row:
            raise HTTPException(status_code=404)
        actor = dict(actor_row)
        actor["short"] = short_id(actor["actor_id"])
        actor["last_seen_fmt"] = fmt_ts(actor.get("last_seen") or "")

        cur.execute("SELECT COUNT(*) as cnt FROM events WHERE actor_id=?", (actor_id,))
        event_count = cur.fetchone()["cnt"]

        cur.execute(
            "SELECT session_id, started_at, ended_at, stage_max, summary FROM sessions WHERE actor_id=? ORDER BY started_at DESC",
            (actor_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["started_fmt"] = fmt_ts(r.get("started_at") or "")
            r["ended_fmt"] = fmt_ts(r.get("ended_at")) if r.get("ended_at") else None

        context = {
            "request": request,
            "actor": actor,
            "sessions": rows,
            "debug": {"event_count": event_count, "sessions_count": len(rows)},
        }
        context.update(_license_context())
        context.update(_license_context())
        return templates.TemplateResponse("actor_sessions.html", context)
    finally:
        conn.close()


@app.get("/dashboard/sessions/{session_id}", response_class=HTMLResponse)
def session_detail(session_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        s = cur.fetchone()
        if not s:
            raise HTTPException(status_code=404)
        sess = dict(s)
        sess["started_fmt"] = fmt_ts(sess.get("started_at") or "")
        sess["ended_fmt"] = fmt_ts(sess.get("ended_at")) if sess.get("ended_at") else "-"
        cur.execute("SELECT * FROM session_steps WHERE session_id=? ORDER BY seq ASC", (session_id,))
        steps = [dict(r) for r in cur.fetchall()]
        sess["duration_seconds"] = None
        sess["duration_ms"] = None
        if sess.get("started_at") and sess.get("ended_at"):
            try:
                start_dt = datetime.fromisoformat(sess["started_at"].replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(sess["ended_at"].replace("Z", "+00:00"))
                sess["duration_seconds"] = max(0, int((end_dt - start_dt).total_seconds()))
            except Exception:
                sess["duration_seconds"] = None
        else:
            # Fallback: derive duration from step timestamps (ms)
            try:
                ts_values = []
                for step in steps:
                    ts = step.get("ts")
                    if ts:
                        ts_values.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                if len(ts_values) >= 2:
                    ts_values.sort()
                    delta = (ts_values[-1] - ts_values[0]).total_seconds()
                    sess["duration_ms"] = max(0, int(delta * 1000))
            except Exception:
                sess["duration_ms"] = None
        open_cases = []
        if _has_feature(licensing.Feature.CASES, action="overview_cases"):
            cur.execute("SELECT id, title, severity, status FROM cases WHERE status='open' ORDER BY updated_at DESC LIMIT 200")
            open_cases = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse(
            "session_detail.html",
            {"request": request, "session": sess, "steps": steps, "cases": open_cases, **_license_context()},
        )
    finally:
        conn.close()


@app.post("/dashboard/campaigns/recompute")
def recompute_campaigns():
    _require_feature(licensing.Feature.CAMPAIGNS)

    conn = db()
    try:
        campaigns_pro.ensure_campaign_pro_state_table(conn)
        if not _campaign_jobs_table_exists(conn):
            raise HTTPException(status_code=503, detail="campaign_jobs table missing; run alembic upgrade head")
        cur = conn.cursor()
        row = cur.execute(
            "SELECT * FROM campaign_jobs WHERE status IN ('queued','running') ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row:
            return {"started": False, "job": _serialize_campaign_job(row)}

        config = campaigns_pro.campaign_config_from_env()
        job_id = os.urandom(8).hex()
        now = _utc_now_iso()
        params_payload = {
            "config": config,
        }
        cur.execute(
            "INSERT INTO campaign_jobs(job_id, status, created_at, params_json) VALUES(?,?,?,?)",
            (job_id, "queued", now, json.dumps(params_payload, ensure_ascii=False)),
        )
        conn.commit()
        campaigns_pro.clear_campaign_tables(conn)
        campaigns_pro.mark_campaign_status(
            conn,
            status=campaigns_pro.PRO_STATUS_PENDING,
            job_id=job_id,
            snapshot_hash="",
        )
    finally:
        conn.close()

    worker = threading.Thread(target=_run_campaign_job, args=(job_id, config), daemon=True, name=f"campaign-job-{job_id}")
    try:
        worker.start()
    except Exception as exc:
        conn = db()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE campaign_jobs SET status=?, finished_at=?, error=? WHERE job_id=?",
                ("failed", _utc_now_iso(), f"worker_start_failed:{exc.__class__.__name__}", job_id),
            )
            conn.commit()
            campaigns_pro.mark_campaign_status(
                conn,
                status=campaigns_pro.PRO_STATUS_UNVERIFIED,
                reason=f"worker_start_failed:{exc.__class__.__name__}",
                job_id=job_id,
            )
        finally:
            conn.close()
        raise HTTPException(status_code=500, detail="campaign_worker_start_failed")

    return {"started": True, "job": {"job_id": job_id, "status": "queued", "created_at": now, "params": params_payload}}


def _campaigns_verification_summary(conn: sqlite3.Connection, backend_enabled: bool) -> dict:
    return campaigns_pro.campaigns_status_summary(conn, backend_enabled=backend_enabled)


@app.get("/dashboard/campaigns/recompute/status")
def recompute_campaigns_status():
    backend_enabled = bool(campaigns_pro.pro_backend_url())
    conn = db()
    try:
        campaigns_pro.ensure_campaign_pro_state_table(conn)
        if not _has_feature(licensing.Feature.CAMPAIGNS, action="campaigns_status"):
            return {
                "status": "disabled",
                "verification": _campaigns_verification_summary(conn, backend_enabled=backend_enabled),
            }
        if not _campaign_jobs_table_exists(conn):
            return {
                "status": "disabled",
                "verification": _campaigns_verification_summary(conn, backend_enabled=backend_enabled),
            }
        cur = conn.cursor()
        row = cur.execute("SELECT * FROM campaign_jobs ORDER BY created_at DESC LIMIT 1").fetchone()
        if not row:
            return {
                "status": "none",
                "verification": _campaigns_verification_summary(conn, backend_enabled=backend_enabled),
            }

        job = _serialize_campaign_job(row)
        job["verification"] = _campaigns_verification_summary(conn, backend_enabled=backend_enabled)
        return job
    finally:
        conn.close()

@app.get("/dashboard/campaigns", response_class=HTMLResponse)
def list_campaigns(request: Request):
    _require_feature(licensing.Feature.CAMPAIGNS)
    backend_enabled = bool(campaigns_pro.pro_backend_url())
    conn = db()
    try:
        campaigns_pro.ensure_campaign_pro_state_table(conn)
        verification = _campaigns_verification_summary(conn, backend_enabled=backend_enabled)
        cur = conn.cursor()
        rows = []
        if verification.get("verified"):
            cur.execute(
                """
                SELECT
                  c.campaign_id,
                  c.label,
                  c.created_at,
                  c.last_seen_at,
                  c.first_seen_at,
                  c.score_det,
                  COUNT(l.actor_id) AS member_count
                FROM campaigns c
                LEFT JOIN campaign_actor_links l ON l.campaign_id = c.campaign_id
                GROUP BY c.campaign_id
                ORDER BY COALESCE(c.last_seen_at, c.created_at) DESC
                """
            )
            rows = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse(
            "campaigns.html",
            {
                "request": request,
                "campaigns": rows,
                "campaigns_pro_state": verification,
                "campaigns_recompute_enabled": True,
                **_license_context(),
            },
        )
    finally:
        conn.close()


@app.get("/dashboard/debug/db")
def debug_db():
    conn = db()
    try:
        cur = conn.cursor()
        
        # check actors
        cur.execute("SELECT COUNT(*) as cnt FROM actors")
        actor_count = cur.fetchone()['cnt']
        
        # check events
        cur.execute("SELECT COUNT(*) as cnt FROM events")
        event_count = cur.fetchone()['cnt']
        
        # check sessions
        cur.execute("SELECT COUNT(*) as cnt FROM sessions")
        session_count = cur.fetchone()['cnt']
        
        # check steps
        cur.execute("SELECT COUNT(*) as cnt FROM session_steps")
        step_count = cur.fetchone()['cnt']
        
        # check cases
        cur.execute("SELECT COUNT(*) as cnt FROM cases")
        case_count = cur.fetchone()['cnt']
        
        # get first actor with events
        cur.execute("SELECT a.actor_id, COUNT(e.id) as event_count FROM actors a LEFT JOIN events e ON a.actor_id=e.actor_id GROUP BY a.actor_id ORDER BY event_count DESC LIMIT 1")
        top_actor = cur.fetchone()
        
        return {
            "actors": actor_count,
            "events": event_count,
            "sessions": session_count,
            "session_steps": step_count,
            "cases": case_count,
            "top_actor": dict(top_actor) if top_actor else None
        }
    finally:
        conn.close()


@app.get("/dashboard/campaigns/{campaign_id}", response_class=HTMLResponse)
def campaign_detail(campaign_id: str, request: Request):
    _require_feature(licensing.Feature.CAMPAIGNS)
    conn = db()
    try:
        if not campaigns_pro.can_render_verified_campaigns(conn, backend_enabled=bool(campaigns_pro.pro_backend_url())):
            raise HTTPException(status_code=404, detail="campaign_result_not_verified")
        cur = conn.cursor()
        cur.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404)
        camp = dict(row)
        try:
            camp["summary"] = json.loads(camp.get("features_summary_json") or "{}")
        except Exception:
            camp["summary"] = {}
        camp["summary"]["stage_flow"] = _sanitize_stage_flow(camp["summary"].get("stage_flow") or "")
        camp["activity"] = _safe_json_loads(camp.get("activity_json"), {})
        camp["timeline"] = _safe_json_loads(camp.get("timeline_json"), {})
        camp["stage_detail"] = _safe_json_loads(camp.get("stage_flow_json"), {})
        camp["techniques"] = _safe_json_loads(camp.get("techniques_json"), [])
        camp["endpoints"] = _safe_json_loads(camp.get("endpoints_json"), [])
        cur.execute("SELECT actor_id, confidence, reasons_json, linked_at FROM campaign_actor_links WHERE campaign_id=?", (campaign_id,))
        links = [dict(r) for r in cur.fetchall()]
        actor_ids = [l["actor_id"] for l in links]
        actor_meta = {}
        if actor_ids:
            placeholders = ",".join(["?"] * len(actor_ids))
            cur.execute(
                f"""
                WITH last_events AS (
                  SELECT e.*
                  FROM events e
                  JOIN (
                    SELECT actor_id, MAX(id) AS max_id
                    FROM events
                    GROUP BY actor_id
                  ) m ON e.actor_id = m.actor_id AND e.id = m.max_id
                )
                SELECT
                  a.actor_id,
                  le.ip AS last_ip,
                  le.ua AS last_ua,
                  le.extra_json AS last_extra_json,
                  (SELECT e.extra_json FROM events e WHERE e.actor_id = a.actor_id AND e.extra_json LIKE '%country_iso2%' ORDER BY e.id DESC LIMIT 1) AS last_geo_extra_json
                FROM actors a
                LEFT JOIN last_events le ON le.actor_id = a.actor_id
                WHERE a.actor_id IN ({placeholders})
                """,
                actor_ids,
            )
            for row in cur.fetchall():
                actor_meta[row["actor_id"]] = dict(row)

        geo_reader = None
        try:
            import geoip2.database
            if os.path.exists(HP_GEOIP_DB):
                geo_reader = geoip2.database.Reader(HP_GEOIP_DB)
        except Exception:
            geo_reader = None

        for link in links:
            try:
                link["reasons"] = json.loads(link.get("reasons_json") or "{}")
            except Exception:
                link["reasons"] = {}
            meta = actor_meta.get(link["actor_id"], {})
            link["last_ip"] = meta.get("last_ip")
            geo = parse_geo_from_extra(meta.get("last_extra_json") or "")
            if not geo.get("geo_iso2"):
                geo = parse_geo_from_extra(meta.get("last_geo_extra_json") or "")
            if not geo.get("geo_iso2") and link.get("last_ip") and geo_reader:
                try:
                    resp = geo_reader.country(link["last_ip"])
                    iso = (resp.country.iso_code or "").strip().upper()
                    name = (resp.country.name or "").strip()
                    if iso:
                        geo["geo_iso2"] = iso
                        geo["geo_name"] = name
                        geo["geo_flag"] = _flag_emoji_from_iso2(iso)
                except Exception:
                    pass
            link.update(geo)
            shared_stage = link["reasons"].get("shared_stage_flow") or ""
            link["reasons"]["shared_stage_flow"] = _sanitize_stage_flow(shared_stage)

        if geo_reader:
            try:
                geo_reader.close()
            except Exception:
                pass
        cur.execute(
            "SELECT id, title, status, severity, updated_at FROM cases WHERE campaign_id=? ORDER BY updated_at DESC",
            (campaign_id,),
        )
        cases = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse(
            "campaign_detail.html",
            {"request": request, "campaign": camp, "links": links, "cases": cases, **_license_context()},
        )
    finally:
        conn.close()


@app.get("/dashboard/actors/{actor_id}/campaign")
def actor_campaign(actor_id: str):
    if not _has_feature(licensing.Feature.CAMPAIGNS, action="actor_campaign_lookup"):
        return {"campaign": None}
    conn = db()
    try:
        if not campaigns_pro.can_render_verified_campaigns(conn, backend_enabled=bool(campaigns_pro.pro_backend_url())):
            return {"campaign": None}
        cur = conn.cursor()
        cur.execute("SELECT campaign_id, confidence, reasons_json FROM campaign_actor_links WHERE actor_id=? ORDER BY confidence DESC LIMIT 1", (actor_id,))
        row = cur.fetchone()
        if not row:
            return {"campaign": None}
        return dict(row)
    finally:
        conn.close()


@app.get("/actor/{actor_id}", response_class=HTMLResponse)
def actor(actor_id: str, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404)

        a = dict(row)
        a["short"] = short_id(a["actor_id"])
        a["stage"] = stage_from_score(int(a.get("score") or 0))
        a["first_seen_fmt"] = fmt_ts(a["first_seen"])
        a["last_seen_fmt"] = fmt_ts(a["last_seen"])

        cur.execute(
            """
            SELECT token, created_ts, stage, gift_type, used_count, last_used_ts
            FROM tokens
            WHERE actor_id=?
            ORDER BY created_ts DESC
            LIMIT 300
            """,
            (actor_id,),
        )
        tokens = [dict(r) for r in cur.fetchall()]
        for t in tokens:
            t["created_fmt"] = fmt_ts(t["created_ts"])
            t["last_used_fmt"] = fmt_ts(t["last_used_ts"]) if t.get("last_used_ts") else None

        cur.execute(
            """
            SELECT id, ts, kind, path, method, ip, ua, body_sample, token, extra_json
            FROM events
            WHERE actor_id=?
            ORDER BY id DESC
            LIMIT 300
            """,
            (actor_id,),
        )
        events = [dict(r) for r in cur.fetchall()]

        geo_reader = None
        try:
            import geoip2.database
            if os.path.exists(HP_GEOIP_DB):
                geo_reader = geoip2.database.Reader(HP_GEOIP_DB)
        except Exception:
            geo_reader = None

        icons = {
            "probe": "\N{RIGHT-POINTING MAGNIFYING GLASS}",
            "health": "\N{GREEN HEART}",
            "token_used": "\N{WHITE HEAVY CHECK MARK}",
            "unknown_token": "\N{BLACK QUESTION MARK ORNAMENT}",
            "keys_issued": "\N{KEY}",
            "internal_config": "\N{GEAR}",
            "backup_list": "\N{FILE CABINET}",
            "backup_download": "\N{DOWNWARDS BLACK ARROW}",
            "admin_secrets": "\N{BRAIN}",
            "infra_vault": "\N{CLASSICAL BUILDING}",
            "cloud_metadata": "\N{CLOUD}",
            "root_console": "\N{CROWN}",
        }
        recon_icon = icons["probe"]

        for e in events:
            e["ts_fmt"] = fmt_ts(e["ts"])
            kind = e.get("kind") or ""
            if kind.startswith("recon_"):
                e["icon"] = recon_icon
            else:
                e["icon"] = icons.get(kind, "\N{BULLET}")
            geo = parse_geo_from_extra(e.get("extra_json") or "")
            if not geo.get("geo_iso2") and e.get("ip") and geo_reader:
                try:
                    resp = geo_reader.country(e["ip"])
                    iso = (resp.country.iso_code or "").strip().upper()
                    name = (resp.country.name or "").strip()
                    if iso:
                        geo["geo_iso2"] = iso
                        geo["geo_name"] = name
                        geo["geo_flag"] = _flag_emoji_from_iso2(iso)
                except Exception:
                    pass
            e.update(geo)

        if geo_reader:
            try:
                geo_reader.close()
            except Exception:
                pass

        cur.execute(
            "SELECT session_id, started_at, stage_max FROM sessions WHERE actor_id=? ORDER BY started_at DESC LIMIT 1",
            (actor_id,),
        )
        latest_session_row = cur.fetchone()
        actor_replay = None
        if latest_session_row:
            actor_replay = dict(latest_session_row)
            actor_replay["started_fmt"] = fmt_ts(actor_replay.get("started_at") or "")
            actor_replay["stage_max"] = actor_replay.get("stage_max") or 0
            a["latest_session_id"] = actor_replay["session_id"]
            a["latest_session_started_fmt"] = actor_replay["started_fmt"]
            a["latest_session_stage"] = actor_replay["stage_max"]

        actor_campaign = None
        if _has_feature(licensing.Feature.CAMPAIGNS, action="actor_detail_campaign") and campaigns_pro.can_render_verified_campaigns(
            conn, backend_enabled=bool(campaigns_pro.pro_backend_url())
        ):
            cur.execute(
                """
                SELECT c.campaign_id, c.label, c.representative_session_id, l.confidence, l.reasons_json
                FROM campaign_actor_links l
                JOIN campaigns c ON c.campaign_id = l.campaign_id
                WHERE l.actor_id=?
                ORDER BY l.confidence DESC
                LIMIT 1
                """,
                (actor_id,),
            )
            campaign_row = cur.fetchone()
            if campaign_row:
                actor_campaign = dict(campaign_row)
                try:
                    actor_campaign["reasons"] = json.loads(actor_campaign.get("reasons_json") or "{}")
                except Exception:
                    actor_campaign["reasons"] = {}

        return templates.TemplateResponse(
            "actor.html",
            {
                "request": request,
                "actor": a,
                "tokens": tokens,
                "events": events,
                "actor_replay": actor_replay,
                "actor_campaign": actor_campaign,
                **_license_context(),
            },
        )
    finally:
        conn.close()
