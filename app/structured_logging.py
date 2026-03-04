"""Structured JSON logging for enterprise / SIEM environments.

Every log record is emitted as a single-line JSON object on stdout and,
optionally, forwarded to a syslog daemon (UDP or TCP) for ingestion by
Splunk, Elastic, Graylog, or any RFC-5424 / CEF receiver.

Configuration (env vars)
------------------------

LOG_LEVEL          Root log level: debug | info | warning | error | critical
                   (default: info)

LOG_FORMAT         Output format: json | text
                   json — one JSON object per line (default in production)
                   text — human-readable (default when LOG_FORMAT is unset
                          and the process is attached to a terminal)

LOG_SYSLOG_HOST    Hostname or IP of the syslog receiver.  When set, a
                   SysLogHandler is added in addition to the console handler.

LOG_SYSLOG_PORT    UDP/TCP port of the syslog receiver (default: 514).

LOG_SYSLOG_SOCKTYPE  tcp | udp  (default: udp)

LOG_SYSLOG_FACILITY  Syslog facility name: user | daemon | local0 … local7
                   (default: user)

Request-ID context
------------------
set_request_id() / get_request_id() propagate a per-request UUID through
Python's contextvars so that every log record emitted while handling that
request automatically carries the correct request_id without needing to pass
it explicitly through the call stack.

Usage in entrypoints
--------------------
    from app.structured_logging import configure_logging
    configure_logging()          # reads env vars internally
    uvicorn.run(..., log_config=None)   # prevent uvicorn from resetting config
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import socket
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Per-request context
# ---------------------------------------------------------------------------

_REQUEST_ID_CTX: ContextVar[str] = ContextVar("request_id", default="")


def get_request_id() -> str:
    """Return the request_id bound to the current async context."""
    return _REQUEST_ID_CTX.get("")


def set_request_id(request_id: str) -> None:
    """Bind *request_id* to the current async context."""
    _REQUEST_ID_CTX.set(request_id)


# ---------------------------------------------------------------------------
# Standard LogRecord attribute names — excluded from the JSON "extra" dump
# ---------------------------------------------------------------------------

_RECORD_ATTRS: frozenset[str] = frozenset(
    (
        "args", "created", "exc_info", "exc_text", "filename", "funcName",
        "levelname", "levelno", "lineno", "message", "module", "msecs",
        "msg", "name", "pathname", "process", "processName", "relativeCreated",
        "stack_info", "taskName", "thread", "threadName",
    )
)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """Format every log record as a single-line JSON object.

    Standard fields always present:

        timestamp   ISO-8601 UTC with millisecond precision
        level       Log level name (INFO, WARNING, …)
        logger      Logger name (e.g. app.honeypot_public)
        message     Formatted log message
        request_id  Per-request UUID from the current async context

    Any keyword arguments passed via ``extra=`` to the logging call are
    merged into the top-level JSON object, overriding the defaults above
    only if the key is not already reserved.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Ensure record.message is populated
        record.message = record.getMessage()

        ts = (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

        doc: dict = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
        }

        # Merge extra fields added by the caller (cannot override reserved keys above)
        _reserved = frozenset(doc.keys())
        for key, value in vars(record).items():
            if key in _RECORD_ATTRS or key.startswith("_"):
                continue
            if key in _reserved:
                continue  # never overwrite timestamp, level, logger, message
            doc[key] = value

        # request_id: honour explicit extra= value first, ContextVar as fallback
        if "request_id" not in doc:
            doc["request_id"] = _REQUEST_ID_CTX.get("")

        if record.exc_info:
            doc["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            doc["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(doc, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Text formatter (dev-friendly)
# ---------------------------------------------------------------------------

_TEXT_FMT = (
    "%(asctime)s.%(msecs)03dZ [%(levelname)-8s] %(name)s %(message)s"
)
_DATE_FMT = "%Y-%m-%dT%H:%M:%S"


class TextFormatter(logging.Formatter):
    """Human-readable formatter that appends key=value pairs from extra."""

    def __init__(self) -> None:
        super().__init__(fmt=_TEXT_FMT, datefmt=_DATE_FMT)

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        base = super().format(record)

        extras = []
        for key, value in vars(record).items():
            if key in _RECORD_ATTRS or key.startswith("_"):
                continue
            if key in ("message", "asctime"):
                continue
            extras.append(f"{key}={value!r}")

        rid = _REQUEST_ID_CTX.get("")
        if rid:
            extras.insert(0, f"request_id={rid!r}")

        if extras:
            return f"{base} {' '.join(extras)}"
        return base


# ---------------------------------------------------------------------------
# Syslog facility map
# ---------------------------------------------------------------------------

_FACILITIES: dict[str, int] = {
    "kern": logging.handlers.SysLogHandler.LOG_KERN,
    "user": logging.handlers.SysLogHandler.LOG_USER,
    "mail": logging.handlers.SysLogHandler.LOG_MAIL,
    "daemon": logging.handlers.SysLogHandler.LOG_DAEMON,
    "auth": logging.handlers.SysLogHandler.LOG_AUTH,
    "lpr": logging.handlers.SysLogHandler.LOG_LPR,
    "news": logging.handlers.SysLogHandler.LOG_NEWS,
    "uucp": logging.handlers.SysLogHandler.LOG_UUCP,
    "cron": logging.handlers.SysLogHandler.LOG_CRON,
    "local0": logging.handlers.SysLogHandler.LOG_LOCAL0,
    "local1": logging.handlers.SysLogHandler.LOG_LOCAL1,
    "local2": logging.handlers.SysLogHandler.LOG_LOCAL2,
    "local3": logging.handlers.SysLogHandler.LOG_LOCAL3,
    "local4": logging.handlers.SysLogHandler.LOG_LOCAL4,
    "local5": logging.handlers.SysLogHandler.LOG_LOCAL5,
    "local6": logging.handlers.SysLogHandler.LOG_LOCAL6,
    "local7": logging.handlers.SysLogHandler.LOG_LOCAL7,
}


# ---------------------------------------------------------------------------
# Public configuration entry point
# ---------------------------------------------------------------------------


def configure_logging(
    *,
    level: Optional[str] = None,
    json_output: Optional[bool] = None,
    syslog_host: Optional[str] = None,
    syslog_port: Optional[int] = None,
    syslog_socktype: Optional[str] = None,
    syslog_facility: Optional[str] = None,
) -> None:
    """Configure the root logger for structured output.

    All parameters fall back to their corresponding environment variables when
    ``None`` (see module docstring for the full list).  Call this once from
    the process entrypoint (``main.py``, ``main_panel.py``) before starting
    uvicorn, with ``log_config=None`` passed to ``uvicorn.run()`` so that
    uvicorn does not reset the configuration.

    Safe to call multiple times (idempotent): existing handlers on the root
    logger are cleared before each call.
    """
    # --- Resolve parameters from env vars -----------------------------------

    level_str = (level or os.environ.get("LOG_LEVEL", "info")).strip().upper()
    log_level: int = getattr(logging, level_str, logging.INFO)

    if json_output is None:
        fmt_env = os.environ.get("LOG_FORMAT", "").strip().lower()
        if fmt_env == "text":
            json_output = False
        elif fmt_env == "json":
            json_output = True
        else:
            # Auto-detect: JSON when stdout is not a TTY (typical in containers)
            json_output = not sys.stdout.isatty()

    if syslog_host is None:
        syslog_host = os.environ.get("LOG_SYSLOG_HOST", "").strip() or None

    if syslog_port is None:
        try:
            syslog_port = int(os.environ.get("LOG_SYSLOG_PORT", "514"))
        except ValueError:
            syslog_port = 514

    if syslog_socktype is None:
        syslog_socktype = os.environ.get("LOG_SYSLOG_SOCKTYPE", "udp").strip().lower()

    if syslog_facility is None:
        syslog_facility = os.environ.get("LOG_SYSLOG_FACILITY", "user").strip().lower()

    # --- Build formatter ----------------------------------------------------

    formatter: logging.Formatter = (
        JsonFormatter() if json_output else TextFormatter()
    )

    # --- Configure root logger ----------------------------------------------

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(log_level)

    # Console handler (stdout — picked up by Docker logging driver / Fluentd)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    # Optional syslog handler for SIEM / log aggregators
    if syslog_host:
        try:
            socktype = socket.SOCK_STREAM if syslog_socktype == "tcp" else socket.SOCK_DGRAM
            facility = _FACILITIES.get(syslog_facility, logging.handlers.SysLogHandler.LOG_USER)
            syslog_handler = logging.handlers.SysLogHandler(
                address=(syslog_host, syslog_port),
                facility=facility,
                socktype=socktype,
            )
            syslog_handler.setFormatter(formatter)
            root.addHandler(syslog_handler)
            root.info(
                "structured_logging: syslog handler configured host=%s port=%d facility=%s",
                syslog_host, syslog_port, syslog_facility,
            )
        except OSError as exc:
            root.warning(
                "structured_logging: could not create syslog handler (%s); "
                "continuing without syslog",
                exc,
            )
