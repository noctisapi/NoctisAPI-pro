from __future__ import annotations

import sqlite3

import pytest

from control_center.runtime import WorkerRuntimeConfig, WorkerRuntimeDisabled, build_worker, run_worker


def test_runtime_is_disabled_by_default_and_does_not_resolve_secrets() -> None:
    config = WorkerRuntimeConfig()
    conn = sqlite3.connect(":memory:")
    try:
        assert run_worker(conn, config=config) == 0
        with pytest.raises(WorkerRuntimeDisabled):
            build_worker(conn, config)
    finally:
        conn.close()


def test_enabled_runtime_builds_empty_read_only_worker_without_secret_backend() -> None:
    config = WorkerRuntimeConfig(enabled=True, worker_id="test-worker", lease_seconds=15)
    conn = sqlite3.connect(":memory:")
    try:
        worker = build_worker(conn, config)
        assert worker._worker_id == "test-worker"
        assert worker._lease_seconds == 15
        assert worker._adapters.providers() == ()
    finally:
        conn.close()


def test_runtime_config_from_env_rejects_invalid_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NOCTISAPI_CONTROL_CENTER_WORKER_LEASE_SECONDS", "0")
    with pytest.raises(ValueError, match="must be positive"):
        WorkerRuntimeConfig.from_env()
