"""Explicit runtime construction for the read-only Control Center worker."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from threading import Event

from scripts.state_security import SecretManager, secret_manager_from_env

from .adapter_factory import AdapterConfiguration, build_adapter_bundle
from .provider_adapters import JsonTransport
from .worker import ReadOnlyReconciliationWorker


class WorkerRuntimeDisabled(RuntimeError):
    """Raised when a caller tries to construct a disabled worker runtime."""


def _required_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _non_negative_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value < 0:
        raise ValueError(f"{name} cannot be negative")
    return value


def _flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class WorkerRuntimeConfig:
    """Process-level settings; disabled by default and read-only by design."""

    enabled: bool = False
    worker_id: str = "control-center-worker"
    lease_seconds: int = 60
    poll_interval: float = 1.0

    @classmethod
    def from_env(cls) -> "WorkerRuntimeConfig":
        worker_id = os.getenv("NOCTISAPI_CONTROL_CENTER_WORKER_ID", cls.worker_id).strip()
        if not worker_id:
            raise ValueError("NOCTISAPI_CONTROL_CENTER_WORKER_ID must not be empty")
        return cls(
            enabled=_flag(os.getenv("NOCTISAPI_CONTROL_CENTER_WORKER_ENABLED")),
            worker_id=worker_id,
            lease_seconds=_required_int("NOCTISAPI_CONTROL_CENTER_WORKER_LEASE_SECONDS", 60),
            poll_interval=_non_negative_float("NOCTISAPI_CONTROL_CENTER_WORKER_POLL_INTERVAL", 1.0),
        )


def build_worker(
    conn: sqlite3.Connection,
    config: WorkerRuntimeConfig,
    *,
    secret_manager: SecretManager | None = None,
    transport: JsonTransport | None = None,
) -> ReadOnlyReconciliationWorker:
    """Build the worker only when explicitly enabled.

    The secret manager is resolved lazily and only when an adapter is enabled.
    This keeps a default web/panel process provider-free and secret-free.
    """

    if not config.enabled:
        raise WorkerRuntimeDisabled("Control Center worker is disabled")

    adapter_config = AdapterConfiguration.from_env()
    needs_secrets = (
        adapter_config.hetzner_enabled
        or adapter_config.cloudflare_enabled
        or bool(adapter_config.billing_provider.strip())
    )
    resolved_secrets = secret_manager
    if needs_secrets and resolved_secrets is None:
        resolved_secrets = secret_manager_from_env()
    bundle = build_adapter_bundle(adapter_config, resolved_secrets, transport=transport)
    return ReadOnlyReconciliationWorker(
        conn,
        bundle.deployments,
        worker_id=config.worker_id,
        lease_seconds=config.lease_seconds,
    )


def run_worker(
    conn: sqlite3.Connection,
    *,
    config: WorkerRuntimeConfig | None = None,
    secret_manager: SecretManager | None = None,
    transport: JsonTransport | None = None,
    stop_event: Event | None = None,
) -> int:
    """Run the explicitly enabled read-only worker until stopped."""

    resolved_config = config or WorkerRuntimeConfig.from_env()
    if not resolved_config.enabled:
        return 0
    worker = build_worker(
        conn,
        resolved_config,
        secret_manager=secret_manager,
        transport=transport,
    )
    return worker.run_forever(
        stop_event=stop_event,
        poll_interval=resolved_config.poll_interval,
    )
