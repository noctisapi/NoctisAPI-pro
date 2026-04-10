# app/pro_router.py
"""
PRO internal router — real backend endpoints, NOT part of the honeypot/deception API.

Routes:
  POST /pro/internal/log-poll   — long-polling log export endpoint (PRO-only)

Strict separation requirements:
  - This router is included in honeypot_public.py but its routes are excluded
    from honeypot event logging and actor tracking (see log_all_requests skip list).
  - Routes are NOT documented in the public OpenAPI schema.
  - No honeypot middleware interferes with these routes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app import licensing
from app import log_export_stream
from app import pro_ops

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB helper (standalone — avoids circular import with honeypot_public)
# ---------------------------------------------------------------------------

_DB_PATH = os.getenv("HP_DB_PATH", "/data/honeypot.db")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False, timeout=5.0, isolation_level="IMMEDIATE")
    conn.row_factory = sqlite3.Row
    for stmt in (
        "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=NORMAL;",
        "PRAGMA busy_timeout=5000;",
        "PRAGMA temp_store=MEMORY;",
    ):
        try:
            conn.execute(stmt)
        except Exception:
            pass
    return conn


# ---------------------------------------------------------------------------
# Rate limiting — simple per-token in-memory sliding window
# ---------------------------------------------------------------------------

_MAX_REQUESTS_PER_MINUTE = int(os.getenv("HP_LOG_EXPORT_RATE_LIMIT", "20") or 20)
# { consumer_id: [timestamp, ...] }
_rate_buckets: dict[int, list[float]] = defaultdict(list)
_RATE_WINDOW = 60.0  # seconds


def _is_rate_limited(consumer_id: int) -> bool:
    if _MAX_REQUESTS_PER_MINUTE <= 0:
        return False
    now = time.monotonic()
    bucket = _rate_buckets[consumer_id]
    # Evict entries outside the window.
    cutoff = now - _RATE_WINDOW
    _rate_buckets[consumer_id] = [t for t in bucket if t >= cutoff]
    if len(_rate_buckets[consumer_id]) >= _MAX_REQUESTS_PER_MINUTE:
        return True
    _rate_buckets[consumer_id].append(now)
    return False


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

_MAX_WAIT_SECONDS = int(os.getenv("HP_LOG_EXPORT_MAX_WAIT", "30") or 30)
_MAX_EVENTS_PER_POLL = 500
_POLL_TICK = 0.5  # seconds between DB checks during long poll


class LogPollRequest(BaseModel):
    cursor: int = Field(0, ge=0, description="Return events after this cursor value")
    max_events: int = Field(100, ge=1, le=500)
    wait_seconds: int = Field(25, ge=0, le=30)


class LogTokenRefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=[])  # No tags — excluded from public OpenAPI


def _log_export_enabled() -> bool:
    ok, _reason = pro_ops.authorize_pro_feature(
        feature=licensing.Feature.LOG_EXPORT.value,
        action="log_export_stream",
        force_refresh=False,
    )
    return bool(ok)


def _build_poll_response(cursor: int, events: list[dict]) -> dict:
    return {"ok": True, "cursor": cursor, "events": events}


@router.post(
    "/pro/internal/log-token/refresh",
    include_in_schema=False,
    response_class=JSONResponse,
)
async def log_token_refresh(body: LogTokenRefreshRequest) -> JSONResponse:
    """
    Rotate the refresh token and issue a short-lived access token.

    On auth failure this returns 404 to avoid leaking consumer identity.
    """
    if not _log_export_enabled():
        return JSONResponse(status_code=404, content={"detail": "Not found"})

    conn = _db()
    try:
        log_export_stream.ensure_tables(conn)
        result = log_export_stream.refresh_consumer_tokens(conn, body.refresh_token.strip())
    finally:
        conn.close()

    if result is None:
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    return JSONResponse(
        status_code=200,
        content={
            "ok": True,
            "token_type": "Bearer",
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "expires_in": result["expires_in"],
            "access_token_expires_at": result["access_token_expires_at"],
            "refresh_token_expires_at": result["refresh_token_expires_at"],
        },
    )


@router.post(
    "/pro/internal/log-poll",
    include_in_schema=False,  # Never appear in honeypot's public OpenAPI docs
    response_class=JSONResponse,
)
async def log_poll(request: Request, body: LogPollRequest) -> JSONResponse:
    """
    Long-polling log export endpoint.

    Authentication:
      Authorization: Bearer nctx_at_<hex>

    On any auth failure the response is 404 to avoid leaking whether
    a consumer identity exists.

    Feature gate:
      Requires PRO tier with LOG_EXPORT feature.  Returns 404 if inactive.
    """
    # ------------------------------------------------------------------
    # 1. Feature gate — checked before touching any DB.
    # ------------------------------------------------------------------
    if not _log_export_enabled():
        return JSONResponse(status_code=404, content={"detail": "Not found"})

    # ------------------------------------------------------------------
    # 2. Extract Bearer token — fail fast and silently.
    # ------------------------------------------------------------------
    auth_header = (request.headers.get("authorization") or "").strip()
    if not auth_header.lower().startswith("bearer "):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    raw_token = auth_header.split(" ", 1)[1].strip()

    # ------------------------------------------------------------------
    # 3. Authenticate consumer — single DB round-trip, return 404 on fail.
    # ------------------------------------------------------------------
    conn = _db()
    try:
        consumer = log_export_stream.authenticate_consumer(conn, raw_token)
    finally:
        conn.close()

    if consumer is None:
        return JSONResponse(status_code=404, content={"detail": "Not found"})

    consumer_id: int = consumer["id"]
    client_ip: str = str(getattr(request.state, "client_ip", None) or "")

    # ------------------------------------------------------------------
    # 4. Rate limit (per consumer, in-memory sliding window).
    # ------------------------------------------------------------------
    if _is_rate_limited(consumer_id):
        _logger.warning(
            "log_export_stream: rate limit hit for consumer_id=%d ip=%s",
            consumer_id,
            client_ip,
        )
        return JSONResponse(
            status_code=429,
            content={"ok": False, "error": "rate_limited"},
        )

    # ------------------------------------------------------------------
    # 5. Validate cursor and poll parameters.
    # ------------------------------------------------------------------
    cursor: int = body.cursor
    max_events: int = min(body.max_events, _MAX_EVENTS_PER_POLL)
    wait_seconds: float = min(float(body.wait_seconds), float(_MAX_WAIT_SECONDS))

    # Check for expired cursor before spending time on long poll.
    conn = _db()
    try:
        if cursor > 0 and log_export_stream.cursor_is_expired(conn, cursor):
            return JSONResponse(
                status_code=200,
                content={"ok": False, "error": "cursor_expired"},
            )
        # Try immediate fetch first.
        events = log_export_stream.get_events_after(conn, cursor, max_events)
    finally:
        conn.close()

    if events:
        new_cursor = events[-1]["cursor"]
        _update_last_used_bg(consumer_id, client_ip)
        payload = _build_poll_response(new_cursor, events)
        if consumer.get("encryption_public_key"):
            encrypted = log_export_stream.encrypt_payload_for_consumer(
                consumer_public_key_pem=str(consumer["encryption_public_key"]),
                plaintext=json.dumps(payload, ensure_ascii=False).encode(),
                key_id=str(consumer.get("encryption_key_id") or ""),
            )
            return JSONResponse(status_code=200, content=encrypted)
        return JSONResponse(status_code=200, content=payload)

    # ------------------------------------------------------------------
    # 6. Long poll — wait up to wait_seconds for new events.
    # ------------------------------------------------------------------
    if wait_seconds <= 0:
        return JSONResponse(
            status_code=200,
            content={"ok": True, "cursor": cursor, "events": []},
        )

    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        await asyncio.sleep(min(_POLL_TICK, max(remaining, 0)))

        conn = _db()
        try:
            events = log_export_stream.get_events_after(conn, cursor, max_events)
        finally:
            conn.close()

        if events:
            new_cursor = events[-1]["cursor"]
            _update_last_used_bg(consumer_id, client_ip)
            payload = _build_poll_response(new_cursor, events)
            if consumer.get("encryption_public_key"):
                encrypted = log_export_stream.encrypt_payload_for_consumer(
                    consumer_public_key_pem=str(consumer["encryption_public_key"]),
                    plaintext=json.dumps(payload, ensure_ascii=False).encode(),
                    key_id=str(consumer.get("encryption_key_id") or ""),
                )
                return JSONResponse(status_code=200, content=encrypted)
            return JSONResponse(status_code=200, content=payload)

    # ------------------------------------------------------------------
    # 7. Timeout — return empty events array with unchanged cursor.
    # ------------------------------------------------------------------
    _update_last_used_bg(consumer_id, client_ip)
    payload = _build_poll_response(cursor, [])
    if consumer.get("encryption_public_key"):
        encrypted = log_export_stream.encrypt_payload_for_consumer(
            consumer_public_key_pem=str(consumer["encryption_public_key"]),
            plaintext=json.dumps(payload, ensure_ascii=False).encode(),
            key_id=str(consumer.get("encryption_key_id") or ""),
        )
        return JSONResponse(status_code=200, content=encrypted)
    return JSONResponse(status_code=200, content=payload)


def _update_last_used_bg(consumer_id: int, ip: str) -> None:
    """Fire-and-forget: update last_used metadata in a background thread."""
    import threading

    def _do() -> None:
        try:
            c = _db()
            try:
                log_export_stream.update_last_used(c, consumer_id, ip)
            finally:
                c.close()
        except Exception as exc:
            _logger.debug("log_export_stream: update_last_used_bg failed: %s", exc)

    threading.Thread(target=_do, daemon=True, name="log-export-last-used").start()
