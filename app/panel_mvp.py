# panel_mvp.py (sin auth, solo protegido por SSH tunnel)
import os
import time
import threading
import json
import sqlite3
from collections import Counter
from statistics import median
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional

from app import status_checks
from app.honeypot_monitor import HoneypotAvailabilityMonitor, get_history as hp_get_history, get_summary as hp_get_summary

APP_NAME = "honeypot-panel-mvp"
DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")
HP_GEOIP_DB = os.getenv("HP_GEOIP_DB", "/data/GeoLite2-Country.mmdb")

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

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


@app.on_event("shutdown")
def _stop_background_tasks():
    honeypot_monitor.stop()


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


def _honeypot_snapshot(conn: sqlite3.Connection, limit: int = 20) -> dict:
    summary = hp_get_summary(
        conn,
        honeypot_monitor.base_url,
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
    return templates.TemplateResponse("honeypot_availability.html", {"request": request, "availability": snapshot})


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
        raise HTTPException(status_code=400, detail="HONEYPOT_PUBLIC_BASE_URL is not configured")
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
            cur.execute(
                "INSERT OR REPLACE INTO campaigns(campaign_id, label, created_at, last_seen_at, score_avg, features_summary_json, representative_session_id) VALUES(?,?,?,?,?,?,?)",
                (cid, label, now, now, 0.0, json.dumps(summary, ensure_ascii=False), rep_session_id),
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
        except Exception as exc:
            err = str(exc)
            try:
                cur.execute(
                    "UPDATE campaign_jobs SET status=?, finished_at=?, error=? WHERE job_id=?",
                    ("failed", _utc_now_iso(), err[:500], job_id),
                )
                conn.commit()
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
              (SELECT COUNT(*) FROM events e WHERE e.actor_id = a.actor_id AND e.kind = 'unknown_token') AS unknown_token_count
            FROM actors a
            LEFT JOIN last_events le ON le.actor_id = a.actor_id
            WHERE COALESCE(a.lifecycle_state, 'active') != 'deleted'
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
            if int(a.get("token_used_count") or 0) > 0:
                a["badges"].append(f"token_used×{a['token_used_count']}")
            if int(a.get("unknown_token_count") or 0) > 0:
                a["badges"].append(f"unknown_token×{a['unknown_token_count']}")

            # errores (desde tabla actors)
            err_total = int(a.get("err_total") or 0)
            err_consec = int(a.get("err_consecutive") or 0)
            a["err_total"] = err_total
            a["err_consecutive"] = err_consec
            a["err_badge"] = f"err×{err_total}" if err_total > 0 else ""

        return templates.TemplateResponse("dashboard.html", {"request": request, "actors": actors, "max_stage": max_stage})
    finally:
        conn.close()


# -------- Dashboard management endpoints: Cases / Sessions / Campaigns --------
@app.get("/dashboard/cases", response_class=HTMLResponse)
def dashboard_cases(request: Request):
    conn = db()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT id, title, severity, status, created_at, updated_at FROM cases ORDER BY updated_at DESC LIMIT 200")
        cases = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse("cases.html", {"request": request, "cases": cases})
    finally:
        conn.close()


@app.get("/dashboard/cases/{case_id}", response_class=HTMLResponse)
def dashboard_case_detail(case_id: int, request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM cases WHERE id=?", (case_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404)
        case = dict(row)
        cur.execute("SELECT actor_id, role, added_at FROM case_actors WHERE case_id=?", (case_id,))
        actors = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT id, ref_type, ref_id, note, added_at FROM case_evidence WHERE case_id=? ORDER BY added_at DESC", (case_id,))
        evidence_rows = [dict(r) for r in cur.fetchall()]

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
                        "SELECT id, session_id, seq, ts, method, path, stage_after, response_status FROM session_steps WHERE id=?",
                        (step_lookup_id,),
                    ).fetchone()
                    if step_row:
                        step = dict(step_row)
                        step["evidence_id"] = ev["id"]
                        step["note"] = ev["note"]
                        step["added_at"] = ev["added_at"]
                        step["ts_fmt"] = fmt_ts(step.get("ts") or "")
                        replay_steps.append(step)
        context = {
            "request": request,
            "case": case,
            "actors": actors,
            "replay_sessions": replay_sessions,
            "replay_steps": replay_steps,
        }
        return templates.TemplateResponse("case_detail.html", context)
    finally:
        conn.close()


@app.post("/dashboard/cases")
def create_case(request: Request):
    title = request.query_params.get("title") or "Untitled"
    description = request.query_params.get("description") or ""
    severity = request.query_params.get("severity") or "low"
    tags = request.query_params.get("tags") or ""
    now = _utc_now_iso()
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO cases(title, description, severity, tags, created_at, updated_at) VALUES(?,?,?,?,?,?)", (title, description, severity, tags, now, now))
        conn.commit()
        new_id = cur.lastrowid
        return {"id": new_id}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/rename")
def rename_case(case_id: int, request: Request):
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


@app.post("/dashboard/cases/{case_id}/actors")
def add_actor_to_case(case_id: int, request: Request):
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

        if ref_type == "session":
            cur.execute("SELECT session_id FROM sessions WHERE session_id=?", (ref_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="session not found")
        else:
            cur.execute("SELECT id FROM session_steps WHERE id=?", (ref_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="step not found")

        cur.execute(
            "INSERT INTO case_evidence(case_id, ref_type, ref_id, note, added_at) VALUES(?,?,?,?,?)",
            (case_id, ref_type, str(ref_id), note, now),
        )
        cur.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/dashboard/cases/{case_id}/evidence/remove")
def remove_case_evidence_entry(case_id: int, request: Request):
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
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, title, status, severity, updated_at FROM cases WHERE status='open' ORDER BY updated_at DESC")
        cases = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse("actor_add_case_modal.html", {"request": request, "actor_id": actor_id, "cases": cases})
    finally:
        conn.close()


@app.post("/dashboard/cases/quick")
def quick_create_case_and_add_actor(request: Request):
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
        return templates.TemplateResponse("actors_deleted.html", {"request": request, "actors": rows})
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
        if sess.get("started_at") and sess.get("ended_at"):
            try:
                start_dt = datetime.fromisoformat(sess["started_at"].replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(sess["ended_at"].replace("Z", "+00:00"))
                sess["duration_seconds"] = max(0, int((end_dt - start_dt).total_seconds()))
            except Exception:
                sess["duration_seconds"] = None
        else:
            sess["duration_seconds"] = None
        cur.execute("SELECT * FROM session_steps WHERE session_id=? ORDER BY seq ASC", (session_id,))
        steps = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT id, title, severity, status FROM cases WHERE status='open' ORDER BY updated_at DESC LIMIT 200")
        open_cases = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse("session_detail.html", {"request": request, "session": sess, "steps": steps, "cases": open_cases})
    finally:
        conn.close()


@app.post("/dashboard/campaigns/recompute")
def recompute_campaigns():
    """
    Agrupa actores con alto overlap en paths recientes usando un Jaccard robusto.
    Evita falsos positivos exigiendo suficientes caminos compartidos y limpia campa??as previas.
    """
    config = {
        "min_features": _env_int("HP_CAMPAIGN_MIN_FEATURES", 4, 1),
        "min_intersection": _env_int("HP_CAMPAIGN_MIN_INTERSECTION", 3, 1),
        "min_jaccard": _env_float("HP_CAMPAIGN_MIN_JACCARD", 0.4, 0.0),
        "max_sessions": _env_int("HP_CAMPAIGN_MAX_SESSIONS", 5, 1),
        "path_ngram_top_k": _env_int("HP_CAMPAIGN_PATH_NGRAM_TOP_K", 12, 1),
        "path_top_k": _env_int("HP_CAMPAIGN_PATH_TOP_K", 10, 1),
        "actor_limit": _env_int("HP_CAMPAIGN_ACTOR_LIMIT", 200, 10),
    }

    conn = db()
    try:
        if not _campaign_jobs_table_exists(conn):
            raise HTTPException(status_code=503, detail="campaign_jobs table missing; run alembic upgrade head")
        cur = conn.cursor()
        row = cur.execute(
            "SELECT * FROM campaign_jobs WHERE status IN ('queued','running') ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row:
            return {"started": False, "job": _serialize_campaign_job(row)}

        import secrets

        job_id = secrets.token_hex(8)
        now = _utc_now_iso()
        cur.execute(
            "INSERT INTO campaign_jobs(job_id, status, created_at, params_json) VALUES(?,?,?,?)",
            (job_id, "queued", now, json.dumps(config, ensure_ascii=False)),
        )
        conn.commit()
    finally:
        conn.close()

    thread = threading.Thread(target=_run_campaign_job, args=(job_id, config), daemon=True)
    thread.start()
    return {"started": True, "job": {"job_id": job_id, "status": "queued", "created_at": now, "params": config}}


@app.get("/dashboard/campaigns/recompute/status")
def recompute_campaigns_status():
    conn = db()
    try:
        if not _campaign_jobs_table_exists(conn):
            return {"status": "disabled"}
        cur = conn.cursor()
        row = cur.execute("SELECT * FROM campaign_jobs ORDER BY created_at DESC LIMIT 1").fetchone()
        if not row:
            return {"status": "none"}
        return _serialize_campaign_job(row)
    finally:
        conn.close()

@app.get("/dashboard/campaigns", response_class=HTMLResponse)
def list_campaigns(request: Request):
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
              c.campaign_id,
              c.label,
              c.created_at,
              c.last_seen_at,
              COUNT(l.actor_id) AS member_count
            FROM campaigns c
            LEFT JOIN campaign_actor_links l ON l.campaign_id = c.campaign_id
            GROUP BY c.campaign_id
            ORDER BY COALESCE(c.last_seen_at, c.created_at) DESC
            """
        )
        rows = [dict(r) for r in cur.fetchall()]
        return templates.TemplateResponse("campaigns.html", {"request": request, "campaigns": rows})
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
    conn = db()
    try:
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
        cur.execute("SELECT actor_id, confidence, reasons_json, linked_at FROM campaign_actor_links WHERE campaign_id=?", (campaign_id,))
        links = [dict(r) for r in cur.fetchall()]
        for link in links:
            try:
                link["reasons"] = json.loads(link.get("reasons_json") or "{}")
            except Exception:
                link["reasons"] = {}
            shared_stage = link["reasons"].get("shared_stage_flow") or ""
            link["reasons"]["shared_stage_flow"] = _sanitize_stage_flow(shared_stage)
        return templates.TemplateResponse("campaign_detail.html", {"request": request, "campaign": camp, "links": links})
    finally:
        conn.close()


@app.get("/dashboard/actors/{actor_id}/campaign")
def actor_campaign(actor_id: str):
    conn = db()
    try:
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
            },
        )
    finally:
        conn.close()
