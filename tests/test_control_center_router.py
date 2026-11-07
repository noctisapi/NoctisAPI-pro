from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from control_center.customers import create_customer
from control_center.router import router


def _app_with_operator(db_path: Path, *, role: str = "viewer") -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def inject_operator(request: Request, call_next):
        request.scope["state"] = {
            "panel_user_id": 1,
            "panel_username": "operator-1",
            "panel_role": role,
        }
        return await call_next(request)

    app.include_router(router)
    return app


def _db(path: Path) -> None:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path.as_posix()}")
    command.upgrade(config, "20261106_03_control_center_billing_costs")
    conn = sqlite3.connect(path)
    customer_id = create_customer(conn, external_id="cus_a", legal_name="Acme", actor_ref="operator-1")
    conn.execute(
        "INSERT INTO cc_deployments(customer_id, external_id, tenant_id, provider, region, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (customer_id, "dep_a", "tenant_a", "hetzner", "fsn1", "2026-11-06T00:00:00Z", "2026-11-06T00:00:00Z"),
    )
    conn.commit()
    conn.close()


def test_control_center_router_reads_are_authenticated_and_scoped(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "control-center.db"
    _db(db_path)
    monkeypatch.setenv("HP_DB_PATH", str(db_path))
    client = TestClient(_app_with_operator(db_path))
    response = client.get("/control-center/customers")
    assert response.status_code == 200
    assert response.json()["items"][0]["external_id"] == "cus_a"


def test_control_center_router_does_not_trust_client_mfa_headers(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "control-center.db"
    _db(db_path)
    monkeypatch.setenv("HP_DB_PATH", str(db_path))
    client = TestClient(_app_with_operator(db_path, role="admin"))
    response = client.post(
        "/control-center/jobs",
        headers={"X-Control-Center-Authn-Level": "sso_mfa"},
        json={"deployment_id": "dep_a", "job_type": "status", "idempotency_key": "req-1"},
    )
    assert response.status_code == 403
    assert "MFA" in response.json()["detail"]
