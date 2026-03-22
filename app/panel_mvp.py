# panel_mvp.py
import hashlib
import hmac as _hmac
import logging
import os
import secrets as _secrets
import time
import threading
import json
import tempfile
import sqlite3
import urllib.request
from app.tls_config import get_ssl_context
from collections import Counter
from statistics import median
from datetime import datetime, timezone

_logger = logging.getLogger(__name__)

from fastapi import FastAPI, Request, HTTPException, Body, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
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
from app import license_online
from app.honeypot_monitor import HoneypotAvailabilityMonitor, get_history as hp_get_history, get_summary as hp_get_summary
from honey_licensing.client import compute_client_identity
from honey_licensing.offline_license import LicenseVerifier, load_public_key_pem
from app.server_config import RequestTimeoutMiddleware, get_request_timeout

APP_NAME = "noctisapi-panel"
DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")
HP_GEOIP_DB = os.getenv("HP_GEOIP_DB", "/data/GeoLite2-Country.mmdb")
HP_PUBLIC_BASE_URL = (os.getenv("HP_PUBLIC_BASE_URL") or "").strip().rstrip("/")
API_CATALOG_LOCK = threading.Lock()
API_CATALOG_CACHE: dict[str, object] = {"ts": 0, "catalog": [], "source": "none", "error": ""}

# Auto-recompute campaigns: set HP_CAMPAIGN_AUTO_RECOMPUTE_THRESHOLD > 0 to enable.
_CAMPAIGN_AUTO_THRESHOLD = int(os.getenv("HP_CAMPAIGN_AUTO_RECOMPUTE_THRESHOLD", "0") or 0)
_CAMPAIGN_AUTO_INTERVAL = int(os.getenv("HP_CAMPAIGN_AUTO_RECOMPUTE_INTERVAL", "3600") or 3600)
# Used to identify internal panelâ†’public requests so they are not logged as actors.
_HP_MONITOR_SECRET = os.getenv("HP_MONITOR_SECRET", "").strip()

# ---------------------------------------------------------------------------
# Panel authentication
# ---------------------------------------------------------------------------
_PANEL_SESSION_COOKIE = "hp_panel_session"
_PANEL_SESSION_TTL = 8 * 3600  # 8 hours
_PANEL_AUTH_BYPASS = {"/health", "/ready", "/login", "/logout"}

_raw_panel_token = os.getenv("HP_PANEL_TOKEN", "").strip()
if not _raw_panel_token:
    _raw_panel_token = _secrets.token_hex(24)
    _logger.warning(
        "HP_PANEL_TOKEN is not set. Panel is using a one-time auto-generated token "
        "for this session: %s  — Set HP_PANEL_TOKEN in your environment to persist "
        "access across restarts.",
        _raw_panel_token,
    )
_PANEL_TOKEN_BYTES = _raw_panel_token.encode()


def _make_session_token() -> str:
    expires = int(time.time()) + _PANEL_SESSION_TTL
    mac = _hmac.new(_PANEL_TOKEN_BYTES, f"panel:{expires}".encode(), "sha256").hexdigest()
    return f"{expires}:{mac}"


def _verify_session_token(token: str) -> bool:
    try:
        expires_str, provided_mac = token.split(":", 1)
        expires = int(expires_str)
        if time.time() > expires:
            return False
        expected_mac = _hmac.new(
            _PANEL_TOKEN_BYTES, f"panel:{expires}".encode(), "sha256"
        ).hexdigest()
        return _hmac.compare_digest(provided_mac, expected_mac)
    except Exception:
        return False


class _PanelAuthMiddleware:
    """ASGI middleware that enforces session-cookie auth on all panel routes."""

    def __init__(self, app_inner):
        self._app = app_inner

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path.startswith("/static/") or path in _PANEL_AUTH_BYPASS:
            await self._app(scope, receive, send)
            return

        headers = {k: v for k, v in scope.get("headers", [])}
        cookie_header = headers.get(b"cookie", b"").decode("latin-1")
        session_token = None
        for part in cookie_header.split(";"):
            name, _, value = part.strip().partition("=")
            if name.strip() == _PANEL_SESSION_COOKIE:
                session_token = value.strip()
                break

        if session_token and _verify_session_token(session_token):
            await self._app(scope, receive, send)
            return

        from urllib.parse import quote as _quote
        redirect_url = f"/login?next={_quote(path, safe='')}"
        resp_headers = [
            (b"location", redirect_url.encode()),
            (b"content-type", b"text/html; charset=utf-8"),
        ]
        await send({"type": "http.response.start", "status": 302, "headers": resp_headers})
        await send({"type": "http.response.body", "body": b"", "more_body": False})


app = FastAPI(title=APP_NAME)
app.add_middleware(RequestTimeoutMiddleware, timeout=get_request_timeout())
app.add_middleware(_PanelAuthMiddleware)
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


def _license_error_hint(error: Optional[str]) -> str:
    code = str(error or "").strip()
    if not code:
        return ""
    if "OFFLINE_LICENSE_MISSING" in code:
        return "No se encontro license.json. Configura HP_OFFLINE_LICENSE_PATH."
    if "LICENSE_SIGNATURE_INVALID" in code or "LICENSE_KID_NOT_TRUSTED" in code:
        return "La firma de license.json no es valida para la clave publica embebida."
    if "LICENSE_EXPIRED" in code:
        return "La licencia esta expirada. Renuevala y reemite un nuevo license.json."
    if "ROLLBACK_DETECTED" in code:
        return "Se detecto rollback de license_generation. Instala la licencia mas reciente."
    if "DEPLOYMENT_MISMATCH" in code:
        return "El deployment_id de la licencia no coincide con esta instancia."
    return "Licencia offline no valida; el sistema funciona en CORE."


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

    app_id = (license_runtime.get_effective("HP_APP_ID") or os.getenv("APP_ID") or "noctisapi-pro").strip()
    app_version = (
        license_runtime.get_effective("HP_APP_VERSION")
        or os.getenv("APP_VERSION")
        or os.getenv("HP_API_VERSION")
        or ""
    ).strip()
    deployment_id = (license_runtime.get_effective("HP_DEPLOYMENT_ID") or os.getenv("HP_DEPLOYMENT_ID") or "").strip()
    license_path = (
        license_runtime.get_effective("HP_OFFLINE_LICENSE_PATH")
        or os.getenv("LICENSING_OFFLINE_LICENSE_PATH")
        or "/var/lib/myapp/license.json"
    ).strip()
    state_path = (
        license_runtime.get_effective("HP_OFFLINE_LICENSE_STATE_PATH")
        or os.getenv("LICENSING_OFFLINE_LICENSE_STATE_PATH")
        or "/var/lib/myapp/license_state.json"
    ).strip()
    keys_path = (
        license_runtime.get_effective("HP_OFFLINE_PUBLIC_KEYS_PATH")
        or os.getenv("LICENSING_OFFLINE_PUBLIC_KEYS_PATH")
        or ""
    ).strip()
    keys_json = (license_runtime.get_effective("HP_OFFLINE_PUBLIC_KEYS_JSON") or "").strip()

    return {
        "runtime_config_path": license_runtime.config_path(),
        "effective": {
            "app_id": app_id,
            "app_version": app_version,
            "deployment_id": deployment_id,
            "offline_license_path": license_path,
            "offline_license_state_path": state_path,
            "offline_public_keys_path": keys_path,
            "offline_public_keys_json_configured": bool(keys_json),
        },
        "sources": {
            "app_id": _source("HP_APP_ID"),
            "app_version": _source("HP_APP_VERSION"),
            "deployment_id": _source("HP_DEPLOYMENT_ID"),
            "offline_license_path": _source("HP_OFFLINE_LICENSE_PATH"),
            "offline_license_state_path": _source("HP_OFFLINE_LICENSE_STATE_PATH"),
            "offline_public_keys_path": _source("HP_OFFLINE_PUBLIC_KEYS_PATH"),
            "offline_public_keys_json": _source("HP_OFFLINE_PUBLIC_KEYS_JSON"),
        },
        "identity": identity,
    }


def _write_json_atomic(path: str, payload: dict) -> None:
    target = str(path or "").strip()
    if not target:
        raise ValueError("license_path_empty")
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="license-upload-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


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
    """Cache is fresh when it was written after (or at) the actor's last activity."""
    cache_dt = _parse_iso(cache_ts)
    last_dt = _parse_iso(last_seen)
    # If last_seen is unknown we can't safely use the cache.
    if not cache_dt or not last_dt:
        return False
    return cache_dt > last_dt


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


def _auto_recompute_campaigns_worker() -> None:
    """Background thread: triggers campaign recompute when enough new events arrive."""
    _logger.info(
        "Campaign auto-recompute enabled: threshold=%d events, interval=%ds",
        _CAMPAIGN_AUTO_THRESHOLD,
        _CAMPAIGN_AUTO_INTERVAL,
    )
    while True:
        try:
            time.sleep(_CAMPAIGN_AUTO_INTERVAL)
            if not _has_feature(licensing.Feature.CAMPAIGNS, action="auto_recompute"):
                continue
            conn = db()
            try:
                if not _campaign_jobs_table_exists(conn):
                    continue
                cur = conn.cursor()
                # Check if any job is already running or queued
                running = cur.execute(
                    "SELECT 1 FROM campaign_jobs WHERE status IN ('queued','running') LIMIT 1"
                ).fetchone()
                if running:
                    continue
                # Count events since last completed job
                last_finished = cur.execute(
                    "SELECT finished_at FROM campaign_jobs WHERE status='completed' ORDER BY finished_at DESC LIMIT 1"
                ).fetchone()
                since_ts = last_finished["finished_at"] if last_finished else "1970-01-01T00:00:00Z"
                new_events = cur.execute(
                    "SELECT COUNT(*) FROM events WHERE ts > ?", (since_ts,)
                ).fetchone()[0]
                if new_events < _CAMPAIGN_AUTO_THRESHOLD:
                    continue
                # Trigger recompute
                config = campaigns_pro.campaign_config_from_env()
                job_id = os.urandom(8).hex()
                now = _utc_now_iso()
                cur.execute(
                    "INSERT INTO campaign_jobs(job_id, status, created_at, params_json) VALUES(?,?,?,?)",
                    (job_id, "queued", now, json.dumps({"config": config}, ensure_ascii=False)),
                )
                conn.commit()
                campaigns_pro.clear_campaign_tables(conn)
                campaigns_pro.mark_campaign_status(
                    conn, status=campaigns_pro.PRO_STATUS_PENDING, job_id=job_id, snapshot_hash=""
                )
                _logger.info(
                    "Auto-recompute triggered: job_id=%s new_events=%d", job_id, new_events
                )
                threading.Thread(
                    target=_run_campaign_job, args=(job_id, config), daemon=True,
                    name=f"campaign-auto-{job_id}"
                ).start()
            except Exception as exc:
                _logger.warning("Auto-recompute check error: %s", exc)
            finally:
                conn.close()
        except Exception as exc:
            _logger.warning("Auto-recompute worker error: %s", exc)


@app.on_event("startup")
def _start_background_tasks():
    import os as _os
    from app.system_settings import load_settings_overrides, ensure_settings_table
    _conn = db()
    try:
        ensure_settings_table(_conn)
        _overrides = load_settings_overrides(_conn)
        for _k, _v in _overrides.items():
            _os.environ[_k] = _v
        if _overrides:
            _logger.info("startup: applied %d config overrides from DB", len(_overrides))
    finally:
        _conn.close()
    from app.egress import check_egress_hosts
    check_egress_hosts()
    from app.diagnostics import run_diagnostics
    run_diagnostics()
    honeypot_monitor.start()
    licensing.set_pro_enabled_provider(pro_license.is_pro_enabled)
    pro_license.get_backend_license_snapshot(force_refresh=True)
    pro_ops.clear_cache()
    if _CAMPAIGN_AUTO_THRESHOLD > 0:
        threading.Thread(
            target=_auto_recompute_campaigns_worker, daemon=True, name="campaign-auto-recompute"
        ).start()


@app.on_event("shutdown")
def _stop_background_tasks():
    honeypot_monitor.stop()
    licensing.set_pro_enabled_provider(None)
    pro_license.clear_cache()
    pro_ops.clear_cache()


@app.get("/login", include_in_schema=False, response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/dashboard", error: str = ""):
    return templates.TemplateResponse(
        "login.html", {"request": request, "next": next, "error": error}
    )


@app.post("/login", include_in_schema=False)
async def login_submit(request: Request):
    form = await request.form()
    token_input = str(form.get("token", "")).strip()
    next_url = str(form.get("next", "/dashboard")).strip() or "/dashboard"
    if not next_url.startswith("/"):
        next_url = "/dashboard"
    if _hmac.compare_digest(token_input.encode(), _PANEL_TOKEN_BYTES):
        session = _make_session_token()
        response = RedirectResponse(url=next_url, status_code=303)
        response.set_cookie(
            _PANEL_SESSION_COOKIE,
            session,
            httponly=True,
            samesite="strict",
            max_age=_PANEL_SESSION_TTL,
            secure=False,  # panel is localhost-only; set True if exposed via TLS proxy
        )
        return response
    from urllib.parse import quote as _quote
    return RedirectResponse(
        url=f"/login?next={_quote(next_url, safe='')}&error=1", status_code=303
    )


@app.post("/logout", include_in_schema=False)
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(_PANEL_SESSION_COOKIE)
    return response


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


@app.get("/dashboard/license", include_in_schema=False)
def dashboard_license_page():
    """Redirect to the dashboard overview which contains the license setup modal."""
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/admin/license", include_in_schema=False, response_class=JSONResponse)
def admin_license_status():
    """
    Internal licensing debug endpoint.

    Intended for the admin service (typically bound to 127.0.0.1 in production).
    Includes both offline and online license state.
    """
    snapshot = _license_runtime_snapshot()
    identity = compute_client_identity()
    online_state = pro_license.get_online_state_snapshot()
    return {
        "pro_enabled": bool(licensing.is_pro_enabled()),
        "feature_flags": licensing.feature_flags(),
        "client_identity": identity,
        "licensing": snapshot,
        "online": online_state,
        "config": _license_config_snapshot(),
        "hint": _license_error_hint(snapshot.get("last_error")),
    }


@app.get("/dashboard/license/online-status", include_in_schema=False, response_class=JSONResponse)
def dashboard_license_online_status():
    """Current online validation state (for admin UI polling)."""
    online_state = pro_license.get_online_state_snapshot()
    mgr = license_online.get_manager()
    return {
        "online_checks_configured": mgr is not None,
        "online_allowed": license_online.is_online_allowed(),
        "pro_enabled": bool(licensing.is_pro_enabled()),
        "state": online_state,
    }


@app.post("/dashboard/license/refresh", include_in_schema=False, response_class=JSONResponse)
def dashboard_license_refresh():
    payload = pro_license.get_backend_license_snapshot(force_refresh=True)
    payload["refreshed"] = bool(payload.get("valid"))
    payload["source"] = "offline_license"
    payload["local_license_ok"] = bool(payload.get("valid"))
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
    _ = payload
    raise HTTPException(status_code=410, detail="license_runtime_config_locked")


@app.post("/dashboard/license/upload", include_in_schema=False, response_class=JSONResponse)
async def dashboard_license_upload(file: UploadFile = File(...)):
    filename = str(file.filename or "").strip()
    if not filename:
        raise HTTPException(status_code=400, detail="license_file_required")
    if not filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="license_file_must_be_json")

    try:
        raw = await file.read()
    except Exception:
        raise HTTPException(status_code=400, detail="license_file_read_failed")
    finally:
        try:
            await file.close()
        except Exception:
            pass

    if not raw:
        raise HTTPException(status_code=400, detail="license_file_empty")
    if len(raw) > (1024 * 1024):
        raise HTTPException(status_code=400, detail="license_file_too_large")

    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except Exception:
        raise HTTPException(status_code=400, detail="license_json_invalid")
    if not isinstance(document, dict):
        raise HTTPException(status_code=400, detail="license_json_invalid")

    try:
        pub_pem = load_public_key_pem()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="offline_public_keys_not_configured")
    verifier = LicenseVerifier(public_key_pem=pub_pem)
    ok_sig, payload, sig_reason = verifier.verify(document)
    if not ok_sig or not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail=sig_reason)

    cfg = _license_config_snapshot()
    license_path = str((cfg.get("effective") or {}).get("offline_license_path") or "").strip()
    if not license_path:
        raise HTTPException(status_code=500, detail="offline_license_path_not_configured")

    try:
        _write_json_atomic(license_path, document)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"license_write_failed:{exc.__class__.__name__}")

    pro_license.clear_cache()
    pro_ops.clear_cache()
    licensing_snapshot = pro_license.get_backend_license_snapshot(force_refresh=True)
    licensing_snapshot["refreshed"] = bool(licensing_snapshot.get("valid"))
    licensing_snapshot["local_license_ok"] = bool(licensing_snapshot.get("valid"))
    if licensing_snapshot.get("last_error"):
        licensing_snapshot["refresh_error"] = licensing_snapshot.get("last_error")
    hint = _license_error_hint(licensing_snapshot.get("refresh_error") or licensing_snapshot.get("last_error"))
    licensing_snapshot["hint"] = hint

    # Trigger an immediate online check so the new license_id is validated right away.
    # Run in a background thread to avoid blocking the upload response.
    mgr = license_online.get_manager()
    if mgr is not None and licensing_snapshot.get("valid"):
        t = threading.Thread(target=mgr.check_now, name="license-online-check-after-upload", daemon=True)
        t.start()

    return {
        "saved": True,
        "license_path": license_path,
        "uploaded_filename": filename,
        "upload_validation": "ok",
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
    """Convierte un cÃ³digo ISO2 de paÃ­s a emoji bandera"""
    if not iso2 or len(iso2) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso2.upper())


def parse_geo_from_extra(extra_json: str):
    """
    Espera algo como:
      {"geo":{"country_iso2":"US","country_name":"United States","flag":"ðŸ‡ºðŸ‡¸"}, ...}
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
    if med < 0.5:
        return "burst"
    if med < 2:
        return "fast"
    if med < 10:
        return "steady"
    if med < 60:
        return "slow"
    return "very_slow"


# Default feature weights — overridden per-run by config signal weight params.
_FEATURE_WEIGHTS: dict[str, float] = {
    "path":   1.0,
    "stage":  1.5,
    "time":   0.8,
    "err":    1.2,
    "ua":     2.0,
    "geo":    0.7,
    "tok":    3.0,
    "hdr":    1.3,
    "subnet": 0.9,
}


def _build_signal_weights(config: dict) -> dict[str, float]:
    """Merge defaults with per-run overrides sourced from campaign config."""
    return {
        "path":   config.get("w_path",   _FEATURE_WEIGHTS["path"]),
        "stage":  config.get("w_stage",  _FEATURE_WEIGHTS["stage"]),
        "time":   config.get("w_time",   _FEATURE_WEIGHTS["time"]),
        "err":    config.get("w_err",    _FEATURE_WEIGHTS["err"]),
        "ua":     config.get("w_ua",     _FEATURE_WEIGHTS["ua"]),
        "geo":    config.get("w_geo",    _FEATURE_WEIGHTS["geo"]),
        "tok":    config.get("w_tok",    _FEATURE_WEIGHTS["tok"]),
        "hdr":    config.get("w_hdr",    _FEATURE_WEIGHTS["hdr"]),
        "subnet": config.get("w_subnet", _FEATURE_WEIGHTS["subnet"]),
    }


def _weighted_jaccard(fp_a: set, fp_b: set, weights: dict[str, float] | None = None) -> float:
    """Weighted Jaccard similarity across multiple signal types.

    Each feature's contribution is multiplied by the weight of its prefix.
    Falls back to module-level _FEATURE_WEIGHTS when *weights* is not given.
    """
    all_features = fp_a | fp_b
    if not all_features:
        return 0.0
    w_map = weights if weights is not None else _FEATURE_WEIGHTS
    inter_sum = 0.0
    union_sum = 0.0
    for f in all_features:
        prefix = f.split("::", 1)[0]
        w = w_map.get(prefix, 1.0)
        union_sum += w
        if f in fp_a and f in fp_b:
            inter_sum += w
    return inter_sum / union_sum if union_sum > 0 else 0.0


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
                "ua": row.get("ua"),
                "ip": row.get("ip"),
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
        params = json.loads(job.get("params_json") or "{}")
        job["params"] = params
        if "campaigns_count" in params:
            job["campaigns_count"] = params["campaigns_count"]
        if "merges_done" in params:
            job["merges_done"] = params["merges_done"]
    except Exception:
        job["params"] = {}
    return job


def _compute_campaigns(conn: sqlite3.Connection, config: dict) -> dict:
    t0 = time.perf_counter()
    features_cached = 0
    features_built = 0
    links_created = 0
    cur = conn.cursor()

    signal_weights = _build_signal_weights(config)
    cache_config_key = campaigns_pro.campaign_cache_config_key(config)

    cache_enabled = True
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

    actor_features: dict[str, set] = {}
    actor_meta: dict[str, dict] = {}

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
                    stored_cfg = cache_obj.get("cache_config_key") or cache_obj.get("config") or {}
                    if stored_cfg == cache_config_key and _is_cache_fresh(cache_row["updated_at"], last_seen):
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
                            "ua_fp": meta.get("ua_fp") or "",
                            "geo_iso2": meta.get("geo_iso2") or "",
                            "token_prefixes": meta.get("token_prefixes") or [],
                            "top_subnets": meta.get("top_subnets") or [],
                            "representative_session_id": meta.get("representative_session_id"),
                        }
                        features_cached += 1
                        continue
                except Exception:
                    pass

        features_built += 1
        features: set[str] = set()
        path_counter: Counter = Counter()
        path_single_counter: Counter = Counter()
        timing_counter: Counter = Counter()
        error_counter: Counter = Counter()
        ua_counter: Counter = Counter()
        geo_counter: Counter = Counter()
        tok_counter: Counter = Counter()
        subnet_counter: Counter = Counter()
        hdr_counter: Counter = Counter()
        rep_session_id = None
        stage_value_counter: Counter = Counter()
        stage_sequence: list = []

        cur.execute(
            "SELECT session_id FROM sessions WHERE actor_id=? ORDER BY started_at DESC LIMIT ?",
            (actor, config["max_sessions"]),
        )
        session_rows = [dict(r) for r in cur.fetchall()]
        for sess_row in session_rows:
            session_id = sess_row["session_id"]
            if not rep_session_id:
                rep_session_id = session_id

            # --- path + timing + error features from session_steps ---
            cur.execute(
                "SELECT seq, ts, path, stage_after, stage_before, response_status, headers_json "
                "FROM session_steps WHERE session_id=? ORDER BY seq ASC LIMIT ?",
                (session_id, config["max_steps_per_session"]),
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
            _stage_flow(stages)

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

            # --- header fingerprint from session_steps ---
            for step in step_rows:
                hdrs_raw = step.get("headers_json") or ""
                if hdrs_raw:
                    try:
                        hdrs = json.loads(hdrs_raw)
                        if isinstance(hdrs, dict):
                            hfp = campaigns_pro.header_fingerprint(hdrs)
                            if hfp:
                                features.add(f"hdr::{hfp}")
                                hdr_counter[hfp] += 1
                    except Exception:
                        pass

        # --- geo / UA / token / subnet from events ---
        cur.execute(
            "SELECT ip, ua, token, extra_json FROM events "
            "WHERE actor_id=? AND ts IS NOT NULL ORDER BY id DESC LIMIT ?",
            (actor, config["max_events_per_actor"]),
        )
        event_rows = [dict(r) for r in cur.fetchall()]
        for ev in event_rows:
            ua_raw = (ev.get("ua") or "").strip()
            if ua_raw:
                ua_counter[ua_raw] += 1
                ua_fp = campaigns_pro.normalize_ua_fingerprint(ua_raw)
                if ua_fp:
                    features.add(f"ua::{ua_fp}")

            tok_raw = (ev.get("token") or "").strip()
            if tok_raw:
                tok_pfx = campaigns_pro.extract_token_prefix(tok_raw)
                if tok_pfx:
                    features.add(f"tok::{tok_pfx}")
                    tok_counter[tok_pfx] += 1

            ip_raw = (ev.get("ip") or "").strip()
            if ip_raw:
                sn = campaigns_pro.ip_subnet(ip_raw)
                if sn:
                    features.add(f"subnet::{sn}")
                    subnet_counter[sn] += 1

            extra_raw = ev.get("extra_json") or ""
            if extra_raw:
                try:
                    extra = json.loads(extra_raw)
                    geo = (extra.get("geo") or {}).get("iso_code") or ""
                    if geo:
                        features.add(f"geo::{geo}")
                        geo_counter[geo] += 1
                except Exception:
                    pass

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

        top_ua_raw = ua_counter.most_common(1)[0][0] if ua_counter else ""
        top_ua_fp = campaigns_pro.normalize_ua_fingerprint(top_ua_raw) if top_ua_raw else ""
        top_geo = geo_counter.most_common(1)[0][0] if geo_counter else ""
        top_tokens = [t for t, _ in tok_counter.most_common(5)]
        top_subnets = [s for s, _ in subnet_counter.most_common(5)]

        actor_features[actor] = features
        actor_meta[actor] = {
            "top_paths": [p for p, _ in path_single_counter.most_common(3)] or [p for p, _ in path_counter.most_common(3)],
            "stage_flow": stage_flow_overall or "",
            "stage_counts": stage_counts,
            "timing": timing_counter.most_common(1)[0][0] if timing_counter else "unknown",
            "errors": [code for code, _ in error_counter.most_common(3)],
            "ua": top_ua_raw,
            "ua_fp": top_ua_fp,
            "geo_iso2": top_geo,
            "token_prefixes": top_tokens,
            "top_subnets": top_subnets,
            "representative_session_id": rep_session_id,
        }
        if cache_enabled:
            cache_payload = {
                "features": list(features),
                "meta": actor_meta[actor],
                "cache_config_key": cache_config_key,
            }
            cur.execute(
                "INSERT OR REPLACE INTO actor_fingerprints(actor_id, fp_json, updated_at) VALUES(?,?,?)",
                (actor, json.dumps(cache_payload, ensure_ascii=False), _utc_now_iso()),
            )

    # First-pass greedy grouping using weighted Jaccard
    campaign_groups: list[dict] = []
    processed: set[str] = set()
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
            score = _weighted_jaccard(fp, other_fp, weights=signal_weights)
            if score >= config["min_jaccard"]:
                group.append(other)
                link_scores[other] = round(score, 3)
                overlap_details[other] = inter_features
        for g in group:
            processed.add(g)
        if len(group) >= 2:
            campaign_groups.append({
                "seed": actor,
                "members": group,
                "link_scores": link_scores,
                "overlap_details": overlap_details,
            })

    # Second merge pass: merge campaign pairs whose seed features are similar
    merges_done = 0
    changed = True
    while changed:
        changed = False
        for i in range(len(campaign_groups)):
            if changed:
                break
            for j in range(i + 1, len(campaign_groups)):
                cA = campaign_groups[i]
                cB = campaign_groups[j]
                fp_a = actor_features.get(cA["seed"], set())
                fp_b = actor_features.get(cB["seed"], set())
                inter = fp_a & fp_b
                if len(inter) < config["min_intersection"]:
                    continue
                if _weighted_jaccard(fp_a, fp_b, weights=signal_weights) >= config["min_jaccard"]:
                    for m in cB["members"]:
                        if m not in cA["members"]:
                            cA["members"].append(m)
                            fp_m = actor_features.get(m, set())
                            cA["link_scores"][m] = round(_weighted_jaccard(fp_a, fp_m, weights=signal_weights), 3)
                            cA["overlap_details"][m] = fp_a & fp_m
                    campaign_groups.pop(j)
                    merges_done += 1
                    changed = True
                    break

    # Atomic swap: delete old campaigns then insert new ones in a single transaction
    cur.execute("DELETE FROM campaign_actor_links")
    cur.execute("DELETE FROM campaigns")
    try:
        cur.execute("UPDATE cases SET campaign_id=NULL WHERE campaign_id IS NOT NULL")
    except Exception:
        pass

    config_key = f"j{config['min_jaccard']:.3f}i{config['min_intersection']}"
    campaigns_created = []
    for grp in campaign_groups:
        actor = grp["seed"]
        group = grp["members"]
        link_scores = grp["link_scores"]
        overlap_details = grp["overlap_details"]

        members_key = "|".join(sorted(group))
        cid = hashlib.sha256(f"{members_key}#{config_key}".encode()).hexdigest()[:16]
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
            "ua_fp": seed_meta.get("ua_fp"),
            "geo_iso2": seed_meta.get("geo_iso2"),
            "token_prefixes": seed_meta.get("token_prefixes"),
            "top_subnets": seed_meta.get("top_subnets"),
            "representative_session_id": rep_session_id,
            "params": config,
        }
        metrics = _campaign_metrics(cur, group)
        summary.update({
            "first_seen": metrics.get("first_seen"),
            "last_seen": metrics.get("last_seen"),
            "activity": metrics.get("activity"),
            "timeline": metrics.get("timeline"),
            "stage": metrics.get("stage"),
            "techniques": metrics.get("techniques"),
            "endpoints": metrics.get("endpoints"),
            "score_det": metrics.get("score_det"),
        })

        # Compute extended metadata
        all_link_scores = [v for v in link_scores.values() if v is not None]
        confidence_score = round(sum(all_link_scores) / len(all_link_scores), 3) if all_link_scores else 0.0

        all_techniques = metrics.get("techniques") or []
        all_endpoints = metrics.get("endpoints") or []
        seed_features = actor_features.get(actor, set())
        behavior_pattern = campaigns_pro.classify_behavior_pattern(
            list(all_techniques), list(all_endpoints), seed_features
        )

        try:
            cur.execute(
                "SELECT COUNT(DISTINCT e.id), COUNT(DISTINCT e.ip) "
                "FROM events e WHERE e.actor_id IN ({}) ".format(",".join("?" * len(group))),
                group,
            )
            cnt_row = cur.fetchone()
            request_count = int(cnt_row[0] or 0) if cnt_row else 0
            ip_diversity = int(cnt_row[1] or 0) if cnt_row else 0
        except Exception:
            request_count = 0
            ip_diversity = 0
        try:
            cur.execute(
                "SELECT COUNT(*) FROM sessions WHERE actor_id IN ({})".format(",".join("?" * len(group))),
                group,
            )
            sc_row = cur.fetchone()
            session_count = int(sc_row[0] or 0) if sc_row else 0
        except Exception:
            session_count = 0

        # Try to INSERT with new columns; fall back to old schema if columns don't exist yet
        try:
            cur.execute(
                """
                INSERT OR REPLACE INTO campaigns(
                    campaign_id, label, created_at, last_seen_at, score_avg, features_summary_json,
                    representative_session_id, first_seen_at, score_det, activity_json, timeline_json,
                    stage_flow_json, techniques_json, endpoints_json,
                    request_count, session_count, confidence_score, behavior_pattern, ip_diversity
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    cid, label, now,
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
                    request_count, session_count, confidence_score, behavior_pattern, ip_diversity,
                ),
            )
        except Exception:
            cur.execute(
                """
                INSERT OR REPLACE INTO campaigns(
                    campaign_id, label, created_at, last_seen_at, score_avg, features_summary_json,
                    representative_session_id, first_seen_at, score_det, activity_json, timeline_json,
                    stage_flow_json, techniques_json, endpoints_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    cid, label, now,
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
            shared_ua_fps = [f.split("ua::", 1)[1] for f in overlaps if f.startswith("ua::")][:3]
            shared_toks = [f.split("tok::", 1)[1] for f in overlaps if f.startswith("tok::")][:3]
            shared_subnets = [f.split("subnet::", 1)[1] for f in overlaps if f.startswith("subnet::")][:3]
            shared_geos = [f.split("geo::", 1)[1] for f in overlaps if f.startswith("geo::")][:5]
            shared_hdrs = [f.split("hdr::", 1)[1] for f in overlaps if f.startswith("hdr::")][:3]
            seed_ua = (actor_meta.get(actor, {}) or {}).get("ua") or ""
            member_ua = (actor_meta.get(a, {}) or {}).get("ua") or ""
            shared_ua = member_ua if seed_ua and member_ua and seed_ua == member_ua else ""
            stage_counts = (actor_meta.get(a, {}) or {}).get("stage_counts", [])

            signal_scores = {}
            for feat in overlaps:
                prefix = feat.split("::", 1)[0] if "::" in feat else ""
                w = signal_weights.get(prefix, 1.0)
                signal_scores[prefix] = round(signal_scores.get(prefix, 0.0) + w, 3)

            reasons = {
                "jaccard_vs_seed": conf,
                "overlap_count": len(overlaps),
                "shared_paths": shared_paths,
                "shared_stage_flow": shared_stage,
                "shared_timing": shared_timing,
                "shared_errors": shared_errors,
                "shared_ua": shared_ua,
                "shared_ua_fps": shared_ua_fps,
                "shared_tokens": shared_toks,
                "shared_subnets": shared_subnets,
                "shared_geos": shared_geos,
                "shared_hdrs": shared_hdrs,
                "stage_counts": stage_counts,
            }
            try:
                cur.execute(
                    "INSERT OR REPLACE INTO campaign_actor_links"
                    "(campaign_id, actor_id, confidence, reasons_json, linked_at, signal_scores_json)"
                    " VALUES(?,?,?,?,?,?)",
                    (cid, a, conf, json.dumps(reasons, ensure_ascii=False), now,
                     json.dumps(signal_scores, ensure_ascii=False)),
                )
            except Exception:
                cur.execute(
                    "INSERT OR REPLACE INTO campaign_actor_links"
                    "(campaign_id, actor_id, confidence, reasons_json, linked_at)"
                    " VALUES(?,?,?,?,?)",
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
        "campaigns_count": len(campaigns_created),
        "merges_done": merges_done,
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
                    json.dumps({"config": config, "campaigns_count": metrics.get("campaigns_count", 0), "merges_done": metrics.get("merges_done", 0)}, ensure_ascii=False),
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
        campaigns_backend_enabled = False
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
        _is_pro_overview = _tier_has_feature(licensing.Feature.ANALYTICS)
        if _is_pro_overview:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt FROM events
                WHERE kind IN (
                  'root_console','cloud_metadata','infra_vault','admin_secrets',
                  'backup_download','backup_list','internal_config','root_shell',
                  'admin_login_attempt','export_users','export_audit','upload_trap',
                  'console_upload','console_exec','devops_webhook','devops_build',
                  'admin_home','admin_users','admin_audit','keys_issued'
                ) AND ts >= datetime('now','-24 hours')
                """
            )
        else:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt FROM events
                WHERE kind IN ('root_console','cloud_metadata','infra_vault')
                  AND ts >= datetime('now','-24 hours')
                """
            )
        alerts_24h = int(cur.fetchone()["cnt"] or 0)
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
                    "alerts_24h": alerts_24h,
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


def _honeypot_public_endpoint_catalog() -> tuple[list[dict], str, str]:
    now = int(time.time())
    with API_CATALOG_LOCK:
        ts = int(API_CATALOG_CACHE.get("ts") or 0)
        cached = API_CATALOG_CACHE.get("catalog")
        if ts > 0 and (now - ts) < 60 and isinstance(cached, list):
            source = str(API_CATALOG_CACHE.get("source") or "cache")
            err = str(API_CATALOG_CACHE.get("error") or "")
            return list(cached), source, err

    def _catalog_from_openapi_doc(doc: dict) -> list[dict]:
        paths = doc.get("paths") if isinstance(doc, dict) else {}
        if not isinstance(paths, dict):
            return []
        seen: set[str] = set()
        out: list[dict] = []
        for path, path_item in paths.items():
            pp = _normalize_catalog_path(path)
            if not isinstance(path_item, dict):
                continue
            for method in sorted(path_item.keys()):
                mm = _normalize_catalog_method(method)
                if mm in {"HEAD", "OPTIONS", "TRACE"}:
                    continue
                key = f"{mm} {pp}"
                if key in seen:
                    continue
                seen.add(key)
                out.append({"method": mm, "path": pp, "label": key})
        out.sort(key=lambda item: (item.get("path") or "", item.get("method") or ""))
        return out

    source = "none"
    last_error = ""
    if HP_PUBLIC_BASE_URL:
        url = f"{HP_PUBLIC_BASE_URL}/openapi.json"
        try:
            _fetch_headers: dict[str, str] = {"accept": "application/json"}
            if _HP_MONITOR_SECRET:
                _fetch_headers["x-internal-monitor"] = _HP_MONITOR_SECRET
            req = urllib.request.Request(url, headers=_fetch_headers)
            with urllib.request.urlopen(req, timeout=3.0, context=get_ssl_context()) as resp:
                raw = resp.read()
            parsed = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
            remote_catalog = _catalog_from_openapi_doc(parsed)
            if remote_catalog:
                with API_CATALOG_LOCK:
                    API_CATALOG_CACHE["ts"] = now
                    API_CATALOG_CACHE["catalog"] = list(remote_catalog)
                    API_CATALOG_CACHE["source"] = "remote_openapi"
                    API_CATALOG_CACHE["error"] = ""
                return remote_catalog, "remote_openapi", ""
        except Exception as exc:
            last_error = f"remote_openapi_failed:{exc.__class__.__name__}"
            source = "remote_openapi_failed"

    # Fallback to local app OpenAPI only when no explicit public base URL is configured.
    try:
        from app.honeypot_public import app as public_api
        local_doc = public_api.openapi()
        local_catalog = _catalog_from_openapi_doc(local_doc if isinstance(local_doc, dict) else {})
        if local_catalog:
            with API_CATALOG_LOCK:
                API_CATALOG_CACHE["ts"] = now
                API_CATALOG_CACHE["catalog"] = list(local_catalog)
                API_CATALOG_CACHE["source"] = "local_openapi"
                API_CATALOG_CACHE["error"] = last_error
            return local_catalog, "local_openapi", last_error
    except Exception:
        if not last_error:
            last_error = "local_openapi_failed"
    with API_CATALOG_LOCK:
        API_CATALOG_CACHE["ts"] = now
        API_CATALOG_CACHE["catalog"] = []
        API_CATALOG_CACHE["source"] = source or "none"
        API_CATALOG_CACHE["error"] = last_error
    return [], (source or "none"), last_error


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
    _ = conn
    _ = limit
    catalog, _source, _err = _honeypot_public_endpoint_catalog()
    return catalog


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
        _cat, catalog_source, catalog_error = _honeypot_public_endpoint_catalog()
    finally:
        conn.close()
    return {
        "templates": api_modular.list_templates(),
        "endpoint_configs": configs,
        "mutation": mutation,
        "rules": rules,
        "endpoint_catalog": endpoint_catalog,
        "endpoint_catalog_source": catalog_source,
        "endpoint_catalog_error": catalog_error,
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
        route_catalog, _catalog_source, _catalog_error = _honeypot_public_endpoint_catalog()
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
        route_catalog, _catalog_source, _catalog_error = _honeypot_public_endpoint_catalog()
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


@app.get("/dashboard/api-modular/resolve", response_class=JSONResponse)
def dashboard_api_modular_resolve(path: str = "/", method: str = "GET"):
    conn = db()
    try:
        ensure_schema(conn)
        api_modular.ensure_tables(conn)
        resolved = api_modular.resolve_endpoint_config(
            conn,
            path=path,
            method=method,
            ensure_schema=False,
        )
        return {
            "path": str(path or "/"),
            "method": str(method or "GET").upper(),
            "resolved": resolved,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)[:200])
    finally:
        conn.close()


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

            # Si no hay flag pero tenemos IP, intentar resolver la geolocalizaciÃ³n
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
            a["err_badge"] = f"errÃ—{err_total}" if err_total > 0 else ""

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
    q = (request.query_params.get("q") or "").strip()
    status_filter = (request.query_params.get("status") or "").strip()
    severity_filter = (request.query_params.get("severity") or "").strip()
    date_from = (request.query_params.get("date_from") or "").strip()
    date_to = (request.query_params.get("date_to") or "").strip()
    techniques_filter = (request.query_params.get("techniques") or "").strip()
    try:
        page = max(1, int(request.query_params.get("page") or 1))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(200, max(1, int(request.query_params.get("per_page") or 50)))
    except (ValueError, TypeError):
        per_page = 50

    conditions: list = []
    params: list = []
    if q:
        conditions.append("title LIKE ?")
        params.append(f"%{q}%")
    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)
    if severity_filter:
        conditions.append("severity = ?")
        params.append(severity_filter)
    if date_from:
        conditions.append("updated_at >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("updated_at <= ?")
        params.append(date_to + "T23:59:59")
    if techniques_filter:
        conditions.append("techniques_json LIKE ?")
        params.append(f'%"{techniques_filter}"%')

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    offset = (page - 1) * per_page

    conn = db()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        total = cur.execute(f"SELECT COUNT(*) FROM cases {where}", params).fetchone()[0]
        cur.execute(
            f"SELECT id, title, severity, status, created_at, updated_at, techniques_json FROM cases {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        )
        cases_raw = cur.fetchall()
        cases = []
        for r in cases_raw:
            c = dict(r)
            try:
                c["techniques"] = json.loads(c.get("techniques_json") or "[]")
            except Exception:
                c["techniques"] = []
            cases.append(c)
        total_pages = max(1, (total + per_page - 1) // per_page)
        return templates.TemplateResponse(
            "cases.html",
            {
                "request": request,
                "cases": cases,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "q": q,
                "status_filter": status_filter,
                "severity_filter": severity_filter,
                "date_from": date_from,
                "date_to": date_to,
                "techniques_filter": techniques_filter,
                **_license_context(),
            },
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

        # Campaigns list for linking â€” only when the feature is licensed AND results are verified.
        campaigns: list[dict] = []
        campaigns_verified = False
        if _has_feature(licensing.Feature.CAMPAIGNS, action="case_detail_campaign_list"):
            try:
                campaigns_pro.ensure_campaign_pro_state_table(conn)
                campaigns_verified = campaigns_pro.can_render_verified_campaigns(
                    conn, backend_enabled=False
                )
                if campaigns_verified:
                    cur.execute(
                        "SELECT campaign_id, label FROM campaigns ORDER BY last_seen_at DESC LIMIT 200"
                    )
                    campaigns = [dict(r) for r in cur.fetchall()]
            except Exception:
                campaigns_verified = False

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
                        "SELECT ss.id, ss.session_id, ss.seq, ss.ts, ss.method, ss.path, ss.stage_after, ss.response_status, ss.headers_json, ss.body_json, ss.response_json, s.actor_id FROM session_steps ss JOIN sessions s ON s.session_id = ss.session_id WHERE ss.id=?",
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
            "campaigns_verified": campaigns_verified,
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
                "headers": _safe_json_loads(step_row["headers_json"], {}),
                "body": _safe_json_loads(step_row["body_json"], None),
                "response_status": step_row["response_status"],
                "response_json": _safe_json_loads(step_row["response_json"], None),
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
        ev["evidence_json"] = _safe_json_loads(ev.get("evidence_json"), None)

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
    stage_info = payload.get("stage_progression") or {}
    lines = [
        f"# Case #{case.get('id')} â€” {case.get('title')}",
        "",
        f"**Status:** {case.get('status')}  ",
        f"**Severity:** {case.get('severity') or 'n/a'}  ",
        f"**Campaign:** `{payload.get('campaign_id') or '-'}`  ",
        f"**Created:** {case.get('created_at')}  ",
        f"**Updated:** {case.get('updated_at')}  ",
    ]
    if case.get("description"):
        lines += ["", f"> {case.get('description')}"]

    # Summary
    lines += [
        "",
        "## Summary",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Risk score | **{payload.get('risk_score')}** |",
        f"| Max stage reached | {stage_info.get('max_stage') or 0} |",
        f"| Stage flow | `{stage_info.get('stage_flow') or '-'}` |",
        f"| Techniques | {', '.join(payload.get('techniques') or []) or '-'} |",
        f"| Top endpoints | {', '.join(payload.get('endpoints') or []) or '-'} |",
        f"| Actors | {len(payload.get('actors') or [])} |",
        f"| Evidence items | {len(payload.get('evidence') or [])} |",
    ]

    # Actors
    lines += ["", "## Actors", ""]
    actors = payload.get("actors") or []
    if actors:
        lines.append("| Actor ID | Role | Added |")
        lines.append("|----------|------|-------|")
        for a in actors:
            lines.append(f"| `{a.get('actor_id')}` | {a.get('role') or 'related'} | {a.get('added_at') or '-'} |")
    else:
        lines.append("_No actors linked._")

    # Stage progression detail
    stage_counts = stage_info.get("stage_counts") or []
    if stage_counts:
        lines += ["", "## Stage Progression", ""]
        lines.append("| Stage | Count |")
        lines.append("|-------|-------|")
        for sc in stage_counts:
            lines.append(f"| {sc.get('stage')} | {sc.get('count')} |")

    # Timeline grouped by session
    timeline = payload.get("timeline") or []
    if timeline:
        lines += ["", "## Timeline", ""]
        current_session = None
        for item in timeline:
            sess = item.get("session_id") or item.get("actor_id") or "unknown"
            if sess != current_session:
                current_session = sess
                lines.append(f"**Session `{sess}`**")
            ts = item.get("ts") or ""
            if item.get("type") == "step":
                lines.append(
                    f"- `{ts}` {item.get('method') or ''} `{item.get('path') or ''}` "
                    f"â†’ {item.get('status') or '-'} (stage {item.get('stage') or '-'})"
                )
            else:
                lines.append(
                    f"- `{ts}` **{item.get('kind') or 'event'}** `{item.get('path') or ''}` "
                    f"â†’ {item.get('status') or '-'}"
                )

    # Evidence breakdown grouped by actor
    evidences = payload.get("evidence") or []
    if evidences:
        lines += ["", "## Evidence", ""]
        by_actor: dict = {}
        for ev in evidences:
            aid = ev.get("actor_id") or "unknown"
            by_actor.setdefault(aid, []).append(ev)
        for aid, evs in by_actor.items():
            lines.append(f"**Actor `{aid}`**")
            for ev in evs:
                note = f" â€” {ev.get('note')}" if ev.get("note") else ""
                lines.append(
                    f"- [{ev.get('ref_type')}] `{ev.get('ref_id')}`"
                    f" {ev.get('source_method') or ''} `{ev.get('source_path') or ''}`"
                    f" stage={ev.get('source_stage') or '-'} status={ev.get('source_status') or '-'}"
                    f"{note}"
                )

    # Similar cases
    if payload.get("similar_cases"):
        lines += ["", "## Similar Cases", ""]
        lines.append("| Case | Score | Shared Actors | Shared Endpoints |")
        lines.append("|------|-------|---------------|-----------------|")
        for sc in payload.get("similar_cases"):
            lines.append(
                f"| [Case #{sc.get('case_id')}](/dashboard/cases/{sc.get('case_id')}) "
                f"| {sc.get('score')} | {sc.get('shared_actors')} | {sc.get('shared_endpoints') or '-'} |"
            )

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
            "SELECT s.session_id, s.started_at, s.ended_at, s.stage_max, s.summary, "
            "COUNT(ss.id) as step_count FROM sessions s "
            "LEFT JOIN session_steps ss ON ss.session_id = s.session_id "
            "WHERE s.actor_id=? GROUP BY s.session_id ORDER BY s.started_at DESC",
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
    # Pro users → interactive replay; Core users → step-by-step legacy view
    if _tier_has_feature(licensing.Feature.REPLAY):
        return RedirectResponse(url=f"/dashboard/replay/{session_id}", status_code=302)
    return RedirectResponse(url=f"/dashboard/sessions/{session_id}/_legacy", status_code=302)


@app.get("/dashboard/sessions/{session_id}/_legacy", response_class=HTMLResponse)
def session_detail_legacy(session_id: str, request: Request):
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
        cur.execute("SELECT COUNT(*) AS cnt FROM session_steps WHERE session_id=?", (session_id,))
        _cnt_row = cur.fetchone()
        steps_total = int(_cnt_row["cnt"] if _cnt_row else 0)
        _steps_cap = 10
        is_pro_session = _tier_has_feature(licensing.Feature.REPLAY)
        if is_pro_session:
            cur.execute("SELECT * FROM session_steps WHERE session_id=? ORDER BY seq ASC", (session_id,))
        else:
            cur.execute("SELECT * FROM session_steps WHERE session_id=? ORDER BY seq ASC LIMIT ?", (session_id, _steps_cap))
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
        evidence_by_step: dict = {}
        session_in_cases: list = []
        if _has_feature(licensing.Feature.CASES, action="overview_cases"):
            cur.execute("SELECT id, title, severity, status FROM cases WHERE status='open' ORDER BY updated_at DESC LIMIT 200")
            open_cases = [dict(r) for r in cur.fetchall()]
            step_ids = [str(s["id"]) for s in steps]
            if step_ids:
                placeholders = ",".join("?" * len(step_ids))
                ev_rows = cur.execute(
                    f"SELECT ce.ref_id, ce.case_id, c.title FROM case_evidence ce "
                    f"JOIN cases c ON c.id = ce.case_id "
                    f"WHERE ce.ref_type='step' AND ce.ref_id IN ({placeholders})",
                    step_ids,
                ).fetchall()
                for row in ev_rows:
                    key = str(row[0])
                    evidence_by_step.setdefault(key, []).append({"case_id": row[1], "title": row[2]})
            si_rows = cur.execute(
                "SELECT ce.case_id, c.title FROM case_evidence ce "
                "JOIN cases c ON c.id = ce.case_id "
                "WHERE ce.ref_type='session' AND ce.ref_id=?",
                (session_id,),
            ).fetchall()
            session_in_cases = [{"case_id": row[0], "title": row[1]} for row in si_rows]
        return templates.TemplateResponse(
            "session_detail.html",
            {"request": request, "session": sess, "steps": steps, "cases": open_cases,
             "evidence_by_step": evidence_by_step, "session_in_cases": session_in_cases,
             "steps_total": steps_total, "steps_cap": _steps_cap,
             **_license_context()},
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
    backend_enabled = False
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
    backend_enabled = False
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
                  c.confidence_score,
                  c.behavior_pattern,
                  c.request_count,
                  c.session_count,
                  c.ip_diversity,
                  COUNT(l.actor_id) AS member_count
                FROM campaigns c
                LEFT JOIN campaign_actor_links l ON l.campaign_id = c.campaign_id
                GROUP BY c.campaign_id
                ORDER BY COALESCE(c.last_seen_at, c.created_at) DESC
                """
            )
            rows = [dict(r) for r in cur.fetchall()]
        job_history = []
        if _campaign_jobs_table_exists(conn):
            job_history = [
                _serialize_campaign_job(r)
                for r in cur.execute(
                    "SELECT * FROM campaign_jobs WHERE status IN ('completed','failed') ORDER BY created_at DESC LIMIT 5"
                ).fetchall()
            ]
        return templates.TemplateResponse(
            "campaigns.html",
            {
                "request": request,
                "campaigns": rows,
                "campaigns_pro_state": verification,
                "campaigns_recompute_enabled": True,
                "job_history": job_history,
                **_license_context(),
            },
        )
    finally:
        conn.close()


@app.get("/dashboard/alerts", response_class=HTMLResponse)
def dashboard_alerts(request: Request, limit: int = 200):
    """High-signal events feed — the value loop output."""
    is_pro = _tier_has_feature(licensing.Feature.ANALYTICS)

    if is_pro:
        _ALERT_KINDS = (
            "root_console", "cloud_metadata", "infra_vault", "admin_secrets",
            "backup_download", "backup_list", "internal_config", "root_shell",
            "admin_login_attempt", "export_users", "export_audit", "upload_trap",
            "console_upload", "console_exec", "devops_webhook", "devops_build",
            "admin_home", "admin_users", "admin_audit", "admin_rotate",
            "internal_access", "internal_reload", "internal_migrate",
            "files_upload", "keys_issued",
        )
        _event_limit = min(int(limit), 500)
        _time_filter = ""
    else:
        # Core: critical-only, 48h window, max 50
        _ALERT_KINDS = ("root_console", "cloud_metadata", "infra_vault")
        _event_limit = 50
        _time_filter = "AND e.ts >= datetime('now', '-48 hours')"

    placeholders = ",".join("?" * len(_ALERT_KINDS))
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT e.id, e.ts, e.actor_id, e.kind, e.path, e.method,
                   e.ip, e.ua, e.status, e.extra_json,
                   COALESCE(a.score, 0) AS actor_score
            FROM events e
            LEFT JOIN actors a ON a.actor_id = e.actor_id
            WHERE e.kind IN ({placeholders})
            {_time_filter}
            ORDER BY e.ts DESC
            LIMIT ?
            """,
            (*_ALERT_KINDS, _event_limit),
        )
        rows = [dict(r) for r in cur.fetchall()]

        # Enrich rows
        for r in rows:
            try:
                ex = json.loads(r.get("extra_json") or "{}")
            except Exception:
                ex = {}
            r["points_delta"] = ex.get("points_delta", "—")
            r["trap_flags"] = ", ".join(ex.get("trap_flags") or []) or "—"
            r["stage_after"] = ex.get("stage_after", "—")
            r["scanner"] = ex.get("scanner", False)

        # Summary stats (24h window regardless of tier)
        cur.execute(
            f"""
            SELECT COUNT(*) AS cnt,
                   COUNT(DISTINCT e.actor_id) AS unique_actors,
                   MAX(e.ts) AS last_seen
            FROM events e
            WHERE e.kind IN ({placeholders})
              AND e.ts >= datetime('now', '-24 hours')
            """,
            _ALERT_KINDS,
        )
        stats_row = cur.fetchone()
        stats = dict(stats_row) if stats_row else {"cnt": 0, "unique_actors": 0, "last_seen": None}

        return templates.TemplateResponse(
            "alerts.html",
            {
                "request": request,
                "events": rows,
                "stats": stats,
                "limit": limit,
                "is_pro": is_pro,
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
        if not campaigns_pro.can_render_verified_campaigns(conn, backend_enabled=False):
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
        cur.execute("SELECT actor_id, confidence, reasons_json, linked_at, signal_scores_json FROM campaign_actor_links WHERE campaign_id=?", (campaign_id,))
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
            link["last_ua"] = meta.get("last_ua")
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
            link["signal_scores"] = _safe_json_loads(link.get("signal_scores_json"), {})

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


def _campaign_export_payload(cur: sqlite3.Cursor, campaign_id: str) -> dict:
    cur.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="campaign not found")
    camp = dict(row)
    try:
        camp["summary"] = json.loads(camp.get("features_summary_json") or "{}")
    except Exception:
        camp["summary"] = {}
    camp["activity"] = _safe_json_loads(camp.get("activity_json"), {})
    camp["timeline"] = _safe_json_loads(camp.get("timeline_json"), {})
    camp["techniques"] = _safe_json_loads(camp.get("techniques_json"), [])
    camp["endpoints"] = _safe_json_loads(camp.get("endpoints_json"), [])
    cur.execute(
        "SELECT actor_id, confidence, reasons_json, linked_at FROM campaign_actor_links WHERE campaign_id=? ORDER BY confidence DESC",
        (campaign_id,),
    )
    links = []
    for r in cur.fetchall():
        link = dict(r)
        link["reasons"] = _safe_json_loads(link.get("reasons_json"), [])
        links.append(link)
    cur.execute(
        "SELECT id, title, status, severity, updated_at FROM cases WHERE campaign_id=? ORDER BY updated_at DESC",
        (campaign_id,),
    )
    cases = [dict(r) for r in cur.fetchall()]
    return {"campaign": camp, "actors": links, "cases": cases}


def _campaign_export_markdown(payload: dict) -> str:
    camp = payload.get("campaign") or {}
    summary = camp.get("summary") or {}
    lines = [
        f"# Campaign `{camp.get('campaign_id')}` â€” {camp.get('label') or 'Unnamed'}",
        "",
        f"**Score:** {camp.get('score_det') or 0}  ",
        f"**First seen:** {camp.get('first_seen_at') or '-'}  ",
        f"**Last seen:** {camp.get('last_seen_at') or '-'}  ",
        f"**Created:** {camp.get('created_at')}  ",
        "",
        "## Summary",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Group size | {summary.get('group_size') or len(payload.get('actors') or [])} |",
        f"| Seed actor | `{summary.get('seed_actor') or '-'}` |",
        f"| Stage flow | `{summary.get('stage_flow') or '-'}` |",
        f"| Timing | {summary.get('timing') or '-'} |",
        f"| Techniques | {', '.join(camp.get('techniques') or []) or '-'} |",
        f"| Top endpoints | {', '.join(camp.get('endpoints') or []) or '-'} |",
        f"| Linked cases | {len(payload.get('cases') or [])} |",
    ]

    # Actors
    actors = payload.get("actors") or []
    lines += ["", "## Actors", ""]
    if actors:
        lines.append("| Actor ID | Confidence | Reasons |")
        lines.append("|----------|------------|---------|")
        for a in actors:
            reasons = ", ".join(str(r) for r in (a.get("reasons") or []))
            lines.append(f"| `{a.get('actor_id')}` | {a.get('confidence') or '-'} | {reasons or '-'} |")
    else:
        lines.append("_No actors linked._")

    # Activity timeline
    activity = camp.get("activity") or {}
    if activity:
        lines += ["", "## Activity by Day", ""]
        lines.append("| Date | Events |")
        lines.append("|------|--------|")
        for date, count in sorted(activity.items()):
            lines.append(f"| {date} | {count} |")

    # Linked cases
    cases = payload.get("cases") or []
    if cases:
        lines += ["", "## Linked Cases", ""]
        lines.append("| Case | Title | Status | Severity |")
        lines.append("|------|-------|--------|----------|")
        for c in cases:
            lines.append(
                f"| [#{c.get('id')}](/dashboard/cases/{c.get('id')}) "
                f"| {c.get('title')} | {c.get('status')} | {c.get('severity') or '-'} |"
            )

    return "\n".join(lines).strip() + "\n"


@app.get("/dashboard/campaigns/{campaign_id}/export.json")
def export_campaign_json(campaign_id: str):
    _require_feature(licensing.Feature.CAMPAIGNS)
    conn = db()
    try:
        cur = conn.cursor()
        payload = _campaign_export_payload(cur, campaign_id)
        return JSONResponse(payload)
    finally:
        conn.close()


@app.get("/dashboard/campaigns/{campaign_id}/export.md", response_class=PlainTextResponse)
def export_campaign_markdown(campaign_id: str):
    _require_feature(licensing.Feature.CAMPAIGNS)
    conn = db()
    try:
        cur = conn.cursor()
        payload = _campaign_export_payload(cur, campaign_id)
        return PlainTextResponse(_campaign_export_markdown(payload))
    finally:
        conn.close()


@app.delete("/dashboard/campaigns/{campaign_id}")
def delete_campaign(campaign_id: str):
    _require_feature(licensing.Feature.CAMPAIGNS)
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM campaign_actor_links WHERE campaign_id=?", (campaign_id,))
        deleted = cur.execute("DELETE FROM campaigns WHERE campaign_id=?", (campaign_id,)).rowcount
        if deleted == 0:
            conn.rollback()
            raise HTTPException(status_code=404, detail="campaign not found")
        # Null out case references to this campaign so no case is left with a stale FK.
        try:
            cur.execute("UPDATE cases SET campaign_id=NULL WHERE campaign_id=?", (campaign_id,))
        except Exception:
            pass
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.get("/dashboard/actors/{actor_id}/campaign")
def actor_campaign(actor_id: str):
    if not _has_feature(licensing.Feature.CAMPAIGNS, action="actor_campaign_lookup"):
        return {"campaign": None}
    conn = db()
    try:
        if not campaigns_pro.can_render_verified_campaigns(conn, backend_enabled=False):
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
            SELECT id, ts, kind, path, method, ip, ua, status, body_sample, token, extra_json
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
            conn, backend_enabled=False
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


# ---------------------------------------------------------------------------
# Environment page
# ---------------------------------------------------------------------------


def _mask_proxy_password(value: str) -> str:
    """Hide password in proxy URLs like http://user:pass@host:port."""
    import re
    return re.sub(r"(https?://[^:@/]+:)[^@/]+(@)", r"\1â€¢â€¢â€¢\2", value)


def _get_env_config(db_overrides: dict[str, str]) -> list[dict]:
    """Build the config view for all editable keys."""
    from app.system_settings import KEY_GROUPS, KEY_LABELS
    groups = []
    for group_name, keys in KEY_GROUPS:
        rows = []
        for key in keys:
            db_val = db_overrides.get(key, "")
            env_val = os.environ.get(key, "")
            if db_val:
                effective = db_val
                source = "override"
            elif env_val:
                effective = env_val
                source = "env"
            else:
                effective = ""
                source = "default"
            # Mask passwords in proxy-like URLs
            display = _mask_proxy_password(effective) if effective else ""
            rows.append({
                "key": key,
                "label": KEY_LABELS.get(key, key),
                "effective": display,
                "source": source,
                "db_value": db_val,
                "env_value": env_val,
            })
        groups.append({"name": group_name, "rows": rows})
    return groups


@app.get("/dashboard/environment", response_class=HTMLResponse)
async def environment_page(request: Request):
    from app.system_settings import load_all_settings, ensure_settings_table
    conn = db()
    try:
        ensure_settings_table(conn)
        db_overrides = load_all_settings(conn)
    finally:
        conn.close()
    config_groups = _get_env_config(db_overrides)
    return templates.TemplateResponse(
        "environment.html",
        {
            "request": request,
            "config_groups": config_groups,
            **_license_context(),
        },
    )


@app.post("/dashboard/environment/settings")
async def environment_save_setting(payload: dict = Body(...)):
    from app.system_settings import save_setting, ensure_settings_table, _EDITABLE_KEYS
    key = str(payload.get("key") or "").strip()
    value = str(payload.get("value") or "").strip()
    if not key or key not in _EDITABLE_KEYS:
        raise HTTPException(status_code=400, detail=f"Key {key!r} is not editable")
    conn = db()
    try:
        ensure_settings_table(conn)
        save_setting(conn, key, value)
    finally:
        conn.close()
    return JSONResponse({"ok": True, "restart_required": True})


@app.post("/dashboard/environment/diagnostics")
async def environment_run_diagnostics():
    from app.diagnostics import run_diagnostics
    diag_results = run_diagnostics()
    hidden_labels = {"outbound HTTPS", "proxy"}
    filtered = [r for r in diag_results if str(r.label or "") not in hidden_labels]
    return JSONResponse({
        "diagnostics": [
            {"label": r.label, "status": r.status, "detail": r.detail}
            for r in filtered
        ],
    })


# ---------------------------------------------------------------------------
# Session Replay — PRO feature
# ---------------------------------------------------------------------------

_REPLAY_HIGH_VALUE_KINDS = frozenset({
    "backup_download", "cloud_metadata", "infra_vault",
    "root_console", "admin_secrets", "internal_config",
})
_REPLAY_WARN_KINDS = frozenset({
    "token_used", "unknown_token", "auth_login", "auth_mfa",
    "keys_issued", "token_issued", "auth_token_request",
})
_REPLAY_RECON_KINDS = frozenset({
    "recon_docs", "recon_openapi", "recon_swagger", "recon_redoc",
    "recon_env", "recon_config", "recon_security", "probe",
})


def _replay_kind_color(kind: str) -> str:
    if kind in _REPLAY_HIGH_VALUE_KINDS:
        return "danger"
    if kind in _REPLAY_WARN_KINDS:
        return "warn"
    if kind in _REPLAY_RECON_KINDS:
        return "recon"
    return "neutral"


def _load_replay_data(conn: sqlite3.Connection, session_id: str) -> dict:
    """Load and enrich all replay data for a session. Returns a dict with
    keys: session, steps, actor_ip, actor_ua, actor_geo, actor_score,
    actor_err_total, total_points.  Raises HTTPException(404) if not found."""
    cur = conn.cursor()

    row = cur.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="session not found")
    sess = dict(row)
    sess["started_fmt"] = fmt_ts(sess.get("started_at") or "")
    sess["ended_fmt"] = fmt_ts(sess.get("ended_at") or "") if sess.get("ended_at") else "—"

    def _parse_dt(s):
        try:
            return datetime.fromisoformat((s or "").replace("Z", "+00:00"))
        except Exception:
            return None

    session_start_dt = _parse_dt(sess.get("started_at"))
    session_end_dt = _parse_dt(sess.get("ended_at"))
    duration_s = None
    if session_start_dt and session_end_dt:
        duration_s = max(0, int((session_end_dt - session_start_dt).total_seconds()))
    sess["duration_s"] = duration_s

    cur.execute(
        "SELECT * FROM session_steps WHERE session_id=? ORDER BY seq ASC",
        (session_id,),
    )
    steps_raw = [dict(r) for r in cur.fetchall()]

    # Load actor events within the session window for enrichment
    events_raw = []
    window_start = sess.get("started_at") or ""
    window_end = sess.get("ended_at") or _utc_now_iso()
    if window_start:
        cur.execute(
            """
            SELECT kind, method, path, ts, token, ip, ua,
                   json_extract(extra_json, '$.latency_ms')        AS latency_ms,
                   json_extract(extra_json, '$.points_delta')       AS points_delta,
                   json_extract(extra_json, '$.geo')                AS geo_json,
                   json_extract(extra_json, '$.trap_flags')         AS trap_flags,
                   json_extract(extra_json, '$.scanner')            AS scanner,
                   json_extract(extra_json, '$.recon')              AS recon,
                   json_extract(extra_json, '$.token_valid')        AS token_valid,
                   json_extract(extra_json, '$.modular')            AS modular_json,
                   json_extract(extra_json, '$.replay_multiplier')  AS replay_multiplier,
                   json_extract(extra_json, '$.err_consecutive')    AS err_consecutive
            FROM events
            WHERE actor_id=? AND ts >= ? AND ts <= ?
            ORDER BY ts ASC
            """,
            (sess["actor_id"], window_start, window_end),
        )
        events_raw = [dict(r) for r in cur.fetchall()]

    # Index events by (method, path) for nearest-timestamp matching
    events_by_key: dict = {}
    for ev in events_raw:
        key = (ev.get("method", ""), ev.get("path", ""))
        events_by_key.setdefault(key, []).append(ev)

    actor_ip = None
    actor_ua = None
    actor_geo: dict = {}
    total_points = 0
    enriched_steps = []
    prev_raw: dict | None = None

    for step in steps_raw:
        enriched = dict(step)
        step_dt = _parse_dt(step.get("ts"))

        # Relative timing for timeline positioning
        if step_dt and session_start_dt:
            offset_ms = max(0, int((step_dt - session_start_dt).total_seconds() * 1000))
            enriched["ts_offset_ms"] = offset_ms
            if duration_s and duration_s > 0:
                enriched["ts_pct"] = min(100.0, round(offset_ms / (duration_s * 1000) * 100, 2))
            else:
                enriched["ts_pct"] = 0.0
        else:
            enriched["ts_offset_ms"] = 0
            enriched["ts_pct"] = 0.0

        # Parse step JSON fields
        enriched["headers"] = _safe_json_loads(step.get("headers_json"), {})
        enriched["query"] = _safe_json_loads(step.get("query_json"), {})
        enriched["body"] = _safe_json_loads(step.get("body_json"), None)
        enriched["response_body"] = _safe_json_loads(step.get("response_json"), None)

        # Match to nearest event
        key = (step.get("method", ""), step.get("path", ""))
        candidates = events_by_key.get(key, [])
        best_ev: dict | None = None
        if candidates:
            if step_dt:
                best_delta = float("inf")
                for ev in candidates:
                    ev_dt = _parse_dt(ev.get("ts"))
                    if ev_dt:
                        delta = abs((ev_dt - step_dt).total_seconds())
                        if delta < best_delta:
                            best_delta = delta
                            best_ev = ev
            else:
                best_ev = candidates[0]

        if best_ev:
            enriched["kind"] = best_ev.get("kind") or "probe"
            enriched["token"] = best_ev.get("token") or ""
            enriched["ip"] = best_ev.get("ip") or ""
            enriched["ua"] = best_ev.get("ua") or ""
            enriched["latency_ms"] = best_ev.get("latency_ms")
            enriched["points_delta"] = int(best_ev.get("points_delta") or 0)
            enriched["trap_flags"] = _safe_json_loads(best_ev.get("trap_flags"), [])
            enriched["scanner"] = bool(best_ev.get("scanner"))
            enriched["recon"] = bool(best_ev.get("recon"))
            enriched["token_valid"] = best_ev.get("token_valid")
            enriched["modular"] = _safe_json_loads(best_ev.get("modular_json"), {})
            enriched["replay_multiplier"] = float(best_ev.get("replay_multiplier") or 1.0)
            enriched["err_consecutive"] = int(best_ev.get("err_consecutive") or 0)
            try:
                geo = json.loads(best_ev.get("geo_json") or "{}")
            except Exception:
                geo = {}
            enriched["geo"] = geo
            if not actor_geo and geo:
                actor_geo = geo
            if not actor_ip:
                actor_ip = best_ev.get("ip")
            if not actor_ua:
                actor_ua = best_ev.get("ua")
            total_points += enriched["points_delta"]
        else:
            enriched.update({
                "kind": "probe", "token": "", "ip": "", "ua": "",
                "latency_ms": None, "points_delta": 0, "trap_flags": [],
                "scanner": False, "recon": False, "token_valid": None,
                "modular": {}, "replay_multiplier": 1.0, "err_consecutive": 0,
                "geo": {},
            })

        enriched["kind_color"] = _replay_kind_color(enriched["kind"])

        # Pre-compute anomalies
        anomalies = []
        if enriched.get("scanner"):
            anomalies.append("scanner_ua")
        if enriched.get("replay_multiplier", 1.0) >= 1.5:
            anomalies.append("replay_bonus")
        sb = enriched.get("stage_before") or 0
        sa = enriched.get("stage_after") or sb
        if sa - sb > 1:
            anomalies.append("stage_jump")
        if enriched["kind"] in _REPLAY_HIGH_VALUE_KINDS:
            anomalies.append("high_value")
        if enriched.get("err_consecutive", 0) >= 5:
            anomalies.append("error_streak")
        if enriched.get("token") and enriched.get("token_valid") is False:
            anomalies.append("invalid_token")
        if prev_raw:
            try:
                prev_dt = _parse_dt(prev_raw.get("ts"))
                if step_dt and prev_dt:
                    gap_ms = (step_dt - prev_dt).total_seconds() * 1000
                    if 0 < gap_ms < 200:
                        anomalies.append("fast_request")
            except Exception:
                pass
        enriched["anomalies"] = anomalies
        enriched_steps.append(enriched)
        prev_raw = step

    # If duration was unknown, distribute steps evenly across timeline
    if not duration_s and len(steps_raw) > 1:
        for i, step in enumerate(enriched_steps):
            step["ts_pct"] = round(i / (len(enriched_steps) - 1) * 100, 2)

    actor_row = cur.execute(
        "SELECT score, err_total FROM actors WHERE actor_id=?",
        (sess["actor_id"],),
    ).fetchone()
    actor_score = actor_row["score"] if actor_row else 0
    actor_err_total = actor_row["err_total"] if actor_row else 0

    return {
        "session": sess,
        "steps": enriched_steps,
        "actor_ip": actor_ip or "",
        "actor_ua": actor_ua or "",
        "actor_geo": actor_geo,
        "actor_score": actor_score,
        "actor_err_total": actor_err_total,
        "total_points": total_points,
    }


@app.get("/dashboard/replay", response_class=HTMLResponse)
def replay_list(request: Request):
    _require_feature(licensing.Feature.REPLAY)

    try:
        page = max(1, int(request.query_params.get("page") or 1))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(100, max(10, int(request.query_params.get("per_page") or 25)))
    except (ValueError, TypeError):
        per_page = 25

    stage_min = (request.query_params.get("stage") or "").strip()
    date_from = (request.query_params.get("date_from") or "").strip()
    date_to = (request.query_params.get("date_to") or "").strip()
    actor_q = (request.query_params.get("actor") or "").strip()

    conditions: list = []
    params: list = []
    if stage_min:
        try:
            conditions.append("s.stage_max >= ?")
            params.append(int(stage_min))
        except (ValueError, TypeError):
            pass
    if date_from:
        conditions.append("s.started_at >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("s.started_at <= ?")
        params.append(date_to + "T23:59:59")
    if actor_q:
        conditions.append("s.actor_id LIKE ?")
        params.append(f"%{actor_q}%")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    offset = (page - 1) * per_page

    conn = db()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        total = cur.execute(f"SELECT COUNT(*) FROM sessions s {where}", params).fetchone()[0]
        cur.execute(
            f"""
            SELECT s.session_id, s.actor_id, s.started_at, s.ended_at,
                   s.stage_max, s.summary, s.fingerprint,
                   (SELECT COUNT(*) FROM session_steps ss
                    WHERE ss.session_id = s.session_id) AS step_count,
                   (SELECT e.ip FROM events e
                    WHERE e.actor_id = s.actor_id AND e.ts >= s.started_at
                    LIMIT 1) AS ip,
                   (SELECT json_extract(e.extra_json, '$.geo')
                    FROM events e
                    WHERE e.actor_id = s.actor_id AND e.ts >= s.started_at
                    LIMIT 1) AS geo_json,
                   (SELECT e.kind FROM events e
                    WHERE e.actor_id = s.actor_id
                      AND e.ts >= s.started_at
                      AND e.kind IN ('root_console','infra_vault','cloud_metadata',
                                     'admin_secrets','backup_download','internal_config',
                                     'keys_issued','token_used','unknown_token')
                    ORDER BY e.ts DESC LIMIT 1) AS top_kind
            FROM sessions s {where}
            ORDER BY s.started_at DESC
            LIMIT ? OFFSET ?
            """,
            params + [per_page, offset],
        )
        sessions = []
        for r in cur.fetchall():
            s = dict(r)
            s["started_fmt"] = fmt_ts(s.get("started_at") or "")
            s["ended_fmt"] = fmt_ts(s.get("ended_at") or "") if s.get("ended_at") else "—"
            started_dt = None
            ended_dt = None
            try:
                started_dt = datetime.fromisoformat((s["started_at"] or "").replace("Z", "+00:00"))
            except Exception:
                pass
            try:
                ended_dt = datetime.fromisoformat((s["ended_at"] or "").replace("Z", "+00:00"))
            except Exception:
                pass
            if started_dt and ended_dt:
                s["duration_s"] = max(0, int((ended_dt - started_dt).total_seconds()))
            else:
                s["duration_s"] = None
            try:
                geo = json.loads(s.get("geo_json") or "{}")
                s["geo_flag"] = geo.get("flag", "")
                s["geo_country"] = geo.get("country_iso2", "")
                s["geo_name"] = geo.get("country_name", "")
            except Exception:
                s["geo_flag"] = ""
                s["geo_country"] = ""
                s["geo_name"] = ""
            s["top_kind_color"] = _replay_kind_color(s.get("top_kind") or "probe")
            sessions.append(s)

        total_pages = max(1, (total + per_page - 1) // per_page)
        return templates.TemplateResponse(
            "replay_list.html",
            {
                "request": request,
                "sessions": sessions,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "stage_min": stage_min,
                "date_from": date_from,
                "date_to": date_to,
                "actor_q": actor_q,
                **_license_context(),
            },
        )
    finally:
        conn.close()


@app.get("/dashboard/replay/{session_id}", response_class=HTMLResponse)
def replay_detail(session_id: str, request: Request):
    _require_feature(licensing.Feature.REPLAY)
    conn = db()
    try:
        ensure_schema(conn)
        data = _load_replay_data(conn, session_id)
        cur = conn.cursor()

        open_cases = []
        if _has_feature(licensing.Feature.CASES, action="overview_cases"):
            cur.execute(
                "SELECT id, title, severity FROM cases WHERE status='open' ORDER BY updated_at DESC LIMIT 100"
            )
            open_cases = [dict(r) for r in cur.fetchall()]

        # Prepare JS-safe step payload (subset; excludes raw *_json columns)
        steps_for_js = []
        for st in data["steps"]:
            steps_for_js.append({
                "id": st.get("id"),
                "seq": st.get("seq"),
                "ts": st.get("ts", ""),
                "ts_offset_ms": st.get("ts_offset_ms", 0),
                "ts_pct": st.get("ts_pct", 0.0),
                "method": st.get("method", ""),
                "path": st.get("path", ""),
                "query": st.get("query") or {},
                "headers": st.get("headers") or {},
                "body": st.get("body"),
                "response_status": st.get("response_status"),
                "response_body": st.get("response_body"),
                "stage_before": st.get("stage_before", 0),
                "stage_after": st.get("stage_after", 0),
                "kind": st.get("kind", "probe"),
                "kind_color": st.get("kind_color", "neutral"),
                "points_delta": st.get("points_delta", 0),
                "latency_ms": st.get("latency_ms"),
                "trap_flags": st.get("trap_flags") or [],
                "scanner": st.get("scanner", False),
                "recon": st.get("recon", False),
                "token": st.get("token", ""),
                "token_valid": st.get("token_valid"),
                "replay_multiplier": st.get("replay_multiplier", 1.0),
                "err_consecutive": st.get("err_consecutive", 0),
                "modular": st.get("modular") or {},
                "anomalies": st.get("anomalies") or [],
            })

        session_js = {
            "session_id": data["session"]["session_id"],
            "actor_id": data["session"]["actor_id"],
            "started_at": data["session"].get("started_at", ""),
            "duration_s": data["session"].get("duration_s"),
            "stage_max": data["session"].get("stage_max", 0),
        }

        return templates.TemplateResponse(
            "replay_detail.html",
            {
                "request": request,
                "session": data["session"],
                "steps": data["steps"],
                "actor_ip": data["actor_ip"],
                "actor_ua": data["actor_ua"],
                "actor_geo": data["actor_geo"],
                "actor_score": data["actor_score"],
                "actor_err_total": data["actor_err_total"],
                "total_points": data["total_points"],
                "cases": open_cases,
                "steps_json": json.dumps(steps_for_js, ensure_ascii=False, default=str),
                "session_json": json.dumps(session_js, ensure_ascii=False, default=str),
                **_license_context(),
            },
        )
    finally:
        conn.close()


@app.get("/api/replay/{session_id}", response_class=JSONResponse)
def api_replay_session(session_id: str):
    _require_feature(licensing.Feature.REPLAY)
    conn = db()
    try:
        ensure_schema(conn)
        data = _load_replay_data(conn, session_id)
        steps_out = []
        for st in data["steps"]:
            steps_out.append({
                "seq": st.get("seq"),
                "ts": st.get("ts"),
                "ts_offset_ms": st.get("ts_offset_ms", 0),
                "method": st.get("method"),
                "path": st.get("path"),
                "query": st.get("query"),
                "headers": st.get("headers"),
                "body": st.get("body"),
                "response_status": st.get("response_status"),
                "stage_before": st.get("stage_before"),
                "stage_after": st.get("stage_after"),
                "kind": st.get("kind"),
                "points_delta": st.get("points_delta"),
                "latency_ms": st.get("latency_ms"),
                "trap_flags": st.get("trap_flags"),
                "anomalies": st.get("anomalies"),
            })
        return {
            "session": {
                "session_id": data["session"]["session_id"],
                "actor_id": data["session"]["actor_id"],
                "started_at": data["session"].get("started_at"),
                "ended_at": data["session"].get("ended_at"),
                "duration_s": data["session"].get("duration_s"),
                "stage_max": data["session"].get("stage_max"),
            },
            "actor": {
                "ip": data["actor_ip"],
                "ua": data["actor_ua"],
                "geo": data["actor_geo"],
                "score": data["actor_score"],
            },
            "total_points": data["total_points"],
            "steps": steps_out,
        }
    finally:
        conn.close()


@app.get("/api/replay/{session_id}/export/ndjson")
def replay_export_ndjson(session_id: str):
    _require_feature(licensing.Feature.REPLAY)
    conn = db()
    try:
        ensure_schema(conn)
        data = _load_replay_data(conn, session_id)
    finally:
        conn.close()

    sess = data["session"]
    lines = []
    for st in data["steps"]:
        record = {
            "session_id": sess["session_id"],
            "actor_id": sess["actor_id"],
            "seq": st.get("seq"),
            "ts": st.get("ts"),
            "method": st.get("method"),
            "path": st.get("path"),
            "query": st.get("query") or {},
            "headers": st.get("headers") or {},
            "body": st.get("body"),
            "response_status": st.get("response_status"),
            "stage_before": st.get("stage_before"),
            "stage_after": st.get("stage_after"),
            "kind": st.get("kind"),
            "points_delta": st.get("points_delta", 0),
            "latency_ms": st.get("latency_ms"),
            "trap_flags": st.get("trap_flags") or [],
            "anomalies": st.get("anomalies") or [],
            "geo": st.get("geo") or {},
        }
        lines.append(json.dumps(record, ensure_ascii=False, default=str))

    short_id = sess["session_id"][:12]
    return Response(
        content="\n".join(lines),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="session_{short_id}.ndjson"'},
    )


@app.get("/api/replay/{session_id}/export/har")
def replay_export_har(session_id: str):
    _require_feature(licensing.Feature.REPLAY)
    conn = db()
    try:
        ensure_schema(conn)
        data = _load_replay_data(conn, session_id)
    finally:
        conn.close()

    sess = data["session"]
    entries = []
    for st in data["steps"]:
        headers_dict = st.get("headers") or {}
        har_headers = [{"name": k, "value": str(v)} for k, v in headers_dict.items()]
        query_dict = st.get("query") or {}
        har_query = [{"name": k, "value": str(v)} for k, v in query_dict.items()]
        body = st.get("body")
        post_data = None
        body_size = -1
        if body is not None:
            body_text = json.dumps(body, default=str) if isinstance(body, (dict, list)) else str(body)
            post_data = {"mimeType": "application/json", "text": body_text}
            body_size = len(body_text.encode("utf-8"))

        entry: dict = {
            "startedDateTime": st.get("ts", ""),
            "time": st.get("latency_ms") or -1,
            "request": {
                "method": st.get("method", "GET"),
                "url": f"https://honeypot{st.get('path', '/')}",
                "httpVersion": "HTTP/1.1",
                "headers": har_headers,
                "queryString": har_query,
                "cookies": [],
                "headersSize": -1,
                "bodySize": body_size,
            },
            "response": {
                "status": st.get("response_status") or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "cookies": [],
                "content": {"size": -1, "mimeType": "application/json"},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": st.get("latency_ms") or -1, "receive": 0},
            "_noctisapi": {
                "kind": st.get("kind", ""),
                "points_delta": st.get("points_delta", 0),
                "stage_before": st.get("stage_before"),
                "stage_after": st.get("stage_after"),
                "actor_id": sess["actor_id"],
                "anomalies": st.get("anomalies") or [],
            },
        }
        if post_data:
            entry["request"]["postData"] = post_data
        entries.append(entry)

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "NoctisAPI Session Replay", "version": "0.1.0"},
            "comment": f"Session {sess['session_id']} — Actor {sess['actor_id']}",
            "entries": entries,
        }
    }
    short_id = sess["session_id"][:12]
    return Response(
        content=json.dumps(har, ensure_ascii=False, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="session_{short_id}.har"'},
    )

