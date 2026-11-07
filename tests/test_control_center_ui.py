from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from control_center.customers import create_customer
from control_center.ui import router


def _app(*, role: str = "viewer") -> FastAPI:
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


def test_control_center_ui_is_read_only(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "control-center.db"
    _db(db_path)
    monkeypatch.setenv("HP_DB_PATH", str(db_path))
    response = TestClient(_app()).get("/control-center/ui?section=inventory")
    assert response.status_code == 200
    assert "dep_a" in response.text
    assert "Read-only phase" in response.text


def test_control_center_ui_requires_session(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "control-center.db"
    _db(db_path)
    monkeypatch.setenv("HP_DB_PATH", str(db_path))
    app = FastAPI()
    app.include_router(router)
    assert TestClient(app).get("/control-center/ui").status_code == 401
