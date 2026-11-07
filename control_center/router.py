"""Authenticated JSON API for the local Control Center surface."""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from .jobs import create_job
from .repository import SQLiteControlCenterReadRepository, connect_sqlite
from .security import ControlCenterAccessError, ControlCenterPrincipal, authorize

router = APIRouter(prefix="/control-center", tags=["Control Center"])


def _db_path() -> str:
    return os.getenv("HP_DB_PATH", "/data/honeypot.db")


def _connect() -> sqlite3.Connection:
    return connect_sqlite(_db_path())


def _principal(request: Request, method: str, path: str) -> ControlCenterPrincipal:
    state = request.scope.get("state") or {}
    user_id = state.get("panel_user_id")
    username = state.get("panel_username")
    role = state.get("panel_role")
    if not user_id or not username or not role:
        raise HTTPException(status_code=401, detail="authenticated operator required")
    # The current session middleware provides session assurance only.  An
    # SSO/MFA adapter must populate this server-side state before mutations
    # can pass control_center.security.authorize; client headers are ignored.
    authn_level = state.get("control_center_authn_level", "session")
    try:
        return authorize(
            method,
            path,
            ControlCenterPrincipal(str(username), str(role), str(authn_level)),
        )
    except ControlCenterAccessError as exc:
        status = 403 if user_id else 401
        raise HTTPException(status_code=status, detail=str(exc)) from exc


def _scope(principal: ControlCenterPrincipal) -> tuple[str, ...]:
    return principal.customer_scope


@router.get("")
def control_center_root(request: Request) -> JSONResponse:
    principal = _principal(request, "GET", "/control-center")
    return JSONResponse(
        {
            "service": "control-center",
            "model_version": 1,
            "operator": principal.subject,
            "capabilities": ["customers", "inventory", "subscriptions", "jobs"],
        }
    )


@router.get("/customers")
def customers(request: Request) -> JSONResponse:
    principal = _principal(request, "GET", "/control-center/customers")
    conn = _connect()
    try:
        repository = SQLiteControlCenterReadRepository(conn)
        return JSONResponse({"items": repository.customers(customer_scope=_scope(principal))})
    finally:
        conn.close()


@router.get("/inventory")
def inventory(request: Request, state: str | None = None) -> JSONResponse:
    principal = _principal(request, "GET", "/control-center/inventory")
    conn = _connect()
    try:
        repository = SQLiteControlCenterReadRepository(conn)
        return JSONResponse({"items": repository.inventory(customer_scope=_scope(principal), state=state)})
    finally:
        conn.close()


@router.get("/subscriptions")
def subscriptions(request: Request) -> JSONResponse:
    principal = _principal(request, "GET", "/control-center/subscriptions")
    conn = _connect()
    try:
        repository = SQLiteControlCenterReadRepository(conn)
        return JSONResponse({"items": repository.subscriptions(customer_scope=_scope(principal))})
    finally:
        conn.close()


@router.post("/jobs", status_code=202)
async def jobs(request: Request) -> JSONResponse:
    principal = _principal(request, "POST", "/control-center/jobs")
    try:
        payload: dict[str, Any] = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="request body must be JSON") from exc
    required = ("deployment_id", "job_type", "idempotency_key")
    if any(not isinstance(payload.get(key), str) or not payload[key].strip() for key in required):
        raise HTTPException(status_code=422, detail="deployment_id, job_type and idempotency_key are required")
    parameters = payload.get("parameters", {})
    if not isinstance(parameters, dict):
        raise HTTPException(status_code=422, detail="parameters must be an object")
    conn = _connect()
    try:
        try:
            job_id = create_job(
                conn,
                deployment_id=payload["deployment_id"],
                job_type=payload["job_type"],
                idempotency_key=payload["idempotency_key"],
                requested_by=principal.subject,
                parameters=parameters,
                confirmation=bool(payload.get("confirmation", False)),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="deployment not found") from exc
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse({"job_id": job_id, "state": "queued"}, status_code=202)
    finally:
        conn.close()
