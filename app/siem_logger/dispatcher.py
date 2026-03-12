from __future__ import annotations

import os
import queue
import threading
from typing import Any, Optional

from .event_schema import make_event
from .json_formatter import to_json_line
from . import stdout_handler, file_handler, syslog_handler

_QUEUE_MAX = 10_000

_q: queue.Queue[str] = queue.Queue(maxsize=_QUEUE_MAX)
_worker_thread: Optional[threading.Thread] = None
_started = False
_start_lock = threading.Lock()
_file_enabled = False
_syslog_enabled = False


def configure() -> None:
    """Read environment variables and start the background dispatch thread."""
    global _file_enabled, _syslog_enabled

    log_output = os.getenv("LOG_OUTPUT", "stdout").lower()
    outputs = {o.strip() for o in log_output.split(",")}

    _file_enabled = "file" in outputs
    if _file_enabled:
        file_handler.configure(
            os.getenv("LOG_FILE_PATH", "/var/log/noctisapi/events.json")
        )

    syslog_raw = os.getenv("SYSLOG_ENABLED", "false").strip().lower()
    _syslog_enabled = syslog_raw in ("1", "true", "yes")
    syslog_handler.configure(
        enabled=_syslog_enabled,
        host=os.getenv("SYSLOG_HOST", ""),
        port=int(os.getenv("SYSLOG_PORT", "514") or 514),
        protocol=os.getenv("SYSLOG_PROTOCOL", "udp"),
        facility_name=os.getenv("SYSLOG_FACILITY", "local0"),
    )

    _ensure_worker()


def _ensure_worker() -> None:
    global _worker_thread, _started
    with _start_lock:
        if _started:
            return
        _worker_thread = threading.Thread(
            target=_drain, daemon=True, name="siem-dispatcher"
        )
        _worker_thread.start()
        _started = True


def _drain() -> None:
    """Background thread: drain the queue and dispatch to all outputs."""
    while True:
        try:
            line = _q.get(timeout=0.2)
        except queue.Empty:
            continue
        try:
            _dispatch(line)
        except Exception:
            pass
        finally:
            try:
                _q.task_done()
            except Exception:
                pass


def _dispatch(line: str) -> None:
    # stdout is mandatory and always emitted
    stdout_handler.emit(line)
    if _file_enabled:
        file_handler.emit(line)
    if _syslog_enabled:
        syslog_handler.emit(line)


def emit(event: dict[str, Any]) -> None:
    """Enqueue a pre-built event dict. Non-blocking — drops on full queue."""
    try:
        line = to_json_line(event)
        _q.put_nowait(line)
    except queue.Full:
        pass  # backpressure: drop rather than block the API
    except Exception:
        pass


def emit_event(
    *,
    kind: str,
    source_ip: str,
    method: str,
    endpoint: str,
    status_code: int,
    user_agent: str,
    interaction_id: str,
    actor_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> None:
    """Build and enqueue a normalized security event. Never raises."""
    try:
        event = make_event(
            kind=kind,
            source_ip=source_ip,
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            user_agent=user_agent,
            interaction_id=interaction_id,
            actor_id=actor_id,
            session_id=session_id,
        )
        emit(event)
    except Exception:
        pass


def shutdown() -> None:
    """Block until the queue is fully drained (for graceful shutdown / tests)."""
    try:
        _q.join()
    except Exception:
        pass
