"""Tests for app.structured_logging — structured JSON logging.

Covers:
 - JsonFormatter:
     * required fields present in every record
       (timestamp, level, logger, message, request_id)
     * timestamp is ISO-8601 UTC with millisecond precision
     * extra= fields merged into JSON output
     * reserved keys not overridden by extra
     * exception info formatted and included
     * output is valid JSON
 - TextFormatter:
     * output is not JSON
     * contains level and message
 - Request-ID ContextVar:
     * get_request_id() returns empty string when not set
     * set_request_id() / get_request_id() round-trip
     * contextvars are isolated between asyncio tasks
 - configure_logging():
     * installs at least one handler on the root logger
     * LOG_LEVEL env var respected
     * LOG_FORMAT=json installs JsonFormatter
     * LOG_FORMAT=text installs TextFormatter
     * invalid syslog host is handled gracefully (no crash)
     * idempotent: multiple calls don't stack handlers
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import unittest

from app.structured_logging import (
    JsonFormatter,
    TextFormatter,
    configure_logging,
    get_request_id,
    set_request_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _EnvOverride:
    _VARS = (
        "LOG_LEVEL", "LOG_FORMAT",
        "LOG_SYSLOG_HOST", "LOG_SYSLOG_PORT",
        "LOG_SYSLOG_SOCKTYPE", "LOG_SYSLOG_FACILITY",
    )

    def __init__(self, **kwargs: str | None):
        self._overrides = kwargs
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self._VARS}
        for k in self._VARS:
            os.environ.pop(k, None)
        for k, v in self._overrides.items():
            if v is not None:
                os.environ[k] = v
        return self

    def __exit__(self, *_):
        for k in self._VARS:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v


def _make_record(
    message: str = "test message",
    level: int = logging.INFO,
    name: str = "test.logger",
    **kwargs,
) -> logging.LogRecord:
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="",
        lineno=0,
        msg=message,
        args=(),
        exc_info=None,
    )
    for k, v in kwargs.items():
        setattr(record, k, v)
    return record


def _format_json(record: logging.LogRecord) -> dict:
    raw = JsonFormatter().format(record)
    return json.loads(raw)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------


class TestJsonFormatterRequiredFields(unittest.TestCase):

    def test_output_is_valid_json(self):
        raw = JsonFormatter().format(_make_record())
        parsed = json.loads(raw)  # must not raise
        self.assertIsInstance(parsed, dict)

    def test_timestamp_present(self):
        doc = _format_json(_make_record())
        self.assertIn("timestamp", doc)

    def test_timestamp_is_utc_iso8601(self):
        doc = _format_json(_make_record())
        ts = doc["timestamp"]
        self.assertTrue(ts.endswith("Z"), f"Expected Z suffix, got {ts!r}")
        # Must be parseable
        from datetime import datetime
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    def test_level_present(self):
        doc = _format_json(_make_record(level=logging.WARNING))
        self.assertEqual(doc["level"], "WARNING")

    def test_logger_present(self):
        doc = _format_json(_make_record(name="app.honeypot_public"))
        self.assertEqual(doc["logger"], "app.honeypot_public")

    def test_message_present(self):
        doc = _format_json(_make_record(message="hello world"))
        self.assertEqual(doc["message"], "hello world")

    def test_request_id_present(self):
        set_request_id("test-req-id")
        try:
            doc = _format_json(_make_record())
            self.assertIn("request_id", doc)
        finally:
            set_request_id("")

    def test_request_id_from_context(self):
        set_request_id("abc-123")
        try:
            doc = _format_json(_make_record())
            self.assertEqual(doc["request_id"], "abc-123")
        finally:
            set_request_id("")

    def test_request_id_empty_when_not_set(self):
        set_request_id("")
        doc = _format_json(_make_record())
        self.assertEqual(doc.get("request_id", ""), "")


class TestJsonFormatterExtraFields(unittest.TestCase):

    def test_extra_fields_merged(self):
        record = _make_record()
        record.client_ip = "1.2.3.4"
        record.method = "GET"
        doc = _format_json(record)
        self.assertEqual(doc["client_ip"], "1.2.3.4")
        self.assertEqual(doc["method"], "GET")

    def test_all_access_log_fields_passthrough(self):
        record = _make_record()
        fields = {
            "client_ip": "10.0.0.1",
            "method": "POST",
            "path": "/api/v1/users",
            "status": 201,
            "user_agent": "curl/7.88",
            "request_id": "req-xyz",
            "x_forwarded_for": "203.0.113.1",
            "cf_connecting_ip": "203.0.113.1",
            "latency_ms": 42,
        }
        for k, v in fields.items():
            setattr(record, k, v)
        doc = _format_json(record)
        for k, v in fields.items():
            self.assertEqual(doc[k], v, f"Field {k!r} mismatch")

    def test_extra_cannot_override_reserved_timestamp(self):
        record = _make_record()
        record.timestamp = "INJECTED"
        doc = _format_json(record)
        self.assertNotEqual(doc["timestamp"], "INJECTED")

    def test_extra_cannot_override_reserved_level(self):
        record = _make_record(level=logging.ERROR)
        record.level = "INJECTED"
        doc = _format_json(record)
        self.assertEqual(doc["level"], "ERROR")

    def test_exception_info_included(self):
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="err", args=(), exc_info=exc_info,
        )
        doc = _format_json(record)
        self.assertIn("exception", doc)
        self.assertIn("ValueError", doc["exception"])

    def test_single_line_output(self):
        raw = JsonFormatter().format(_make_record())
        self.assertNotIn("\n", raw)


# ---------------------------------------------------------------------------
# TextFormatter
# ---------------------------------------------------------------------------


class TestTextFormatter(unittest.TestCase):

    def test_output_is_not_json(self):
        raw = TextFormatter().format(_make_record())
        with self.assertRaises((json.JSONDecodeError, ValueError)):
            json.loads(raw)

    def test_contains_level(self):
        raw = TextFormatter().format(_make_record(level=logging.WARNING))
        self.assertIn("WARNING", raw)

    def test_contains_message(self):
        raw = TextFormatter().format(_make_record(message="hello text"))
        self.assertIn("hello text", raw)

    def test_extra_fields_appended(self):
        record = _make_record()
        record.status = 200
        raw = TextFormatter().format(record)
        self.assertIn("status=", raw)


# ---------------------------------------------------------------------------
# ContextVar: get_request_id / set_request_id
# ---------------------------------------------------------------------------


class TestRequestIdContextVar(unittest.TestCase):

    def setUp(self):
        set_request_id("")

    def test_default_is_empty_string(self):
        set_request_id("")
        self.assertEqual(get_request_id(), "")

    def test_set_and_get_roundtrip(self):
        set_request_id("my-request-id")
        self.assertEqual(get_request_id(), "my-request-id")

    def test_different_tasks_have_independent_ids(self):
        results = {}

        async def task_a():
            set_request_id("id-a")
            await asyncio.sleep(0)
            results["a"] = get_request_id()

        async def task_b():
            set_request_id("id-b")
            await asyncio.sleep(0)
            results["b"] = get_request_id()

        async def main():
            await asyncio.gather(task_a(), task_b())

        _run(main())
        self.assertEqual(results["a"], "id-a")
        self.assertEqual(results["b"], "id-b")

    def test_reset_to_empty(self):
        set_request_id("existing")
        set_request_id("")
        self.assertEqual(get_request_id(), "")


# ---------------------------------------------------------------------------
# configure_logging()
# ---------------------------------------------------------------------------


class TestConfigureLogging(unittest.TestCase):

    def tearDown(self):
        # Restore root logger to a sane state after each test
        root = logging.getLogger()
        root.handlers.clear()
        root.setLevel(logging.WARNING)

    def test_installs_at_least_one_handler(self):
        with _EnvOverride(LOG_FORMAT="text"):
            configure_logging()
        self.assertGreater(len(logging.getLogger().handlers), 0)

    def test_log_level_info_by_default(self):
        with _EnvOverride():
            configure_logging()
        self.assertEqual(logging.getLogger().level, logging.INFO)

    def test_log_level_from_env(self):
        with _EnvOverride(LOG_LEVEL="debug"):
            configure_logging()
        self.assertEqual(logging.getLogger().level, logging.DEBUG)

    def test_log_level_warning(self):
        with _EnvOverride(LOG_LEVEL="warning"):
            configure_logging()
        self.assertEqual(logging.getLogger().level, logging.WARNING)

    def test_json_format_installs_json_formatter(self):
        with _EnvOverride(LOG_FORMAT="json"):
            configure_logging()
        handler = logging.getLogger().handlers[0]
        self.assertIsInstance(handler.formatter, JsonFormatter)

    def test_text_format_installs_text_formatter(self):
        with _EnvOverride(LOG_FORMAT="text"):
            configure_logging()
        handler = logging.getLogger().handlers[0]
        self.assertIsInstance(handler.formatter, TextFormatter)

    def test_idempotent_handlers_not_stacked(self):
        with _EnvOverride(LOG_FORMAT="text"):
            configure_logging()
            configure_logging()
        # Should only have the console handler, not two of them
        self.assertEqual(len(logging.getLogger().handlers), 1)

    def test_invalid_syslog_host_does_not_crash(self):
        with _EnvOverride(LOG_SYSLOG_HOST="255.255.255.255", LOG_SYSLOG_PORT="1"):
            try:
                configure_logging()
            except Exception as exc:
                self.fail(f"configure_logging() raised {exc!r} with bad syslog host")

    def test_json_output_is_valid_json(self):
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(JsonFormatter())
        logger = logging.getLogger("test_json_output")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.info("structured test message", extra={"status": 200})
        logger.removeHandler(handler)

        output = buf.getvalue().strip()
        doc = json.loads(output)
        self.assertEqual(doc["message"], "structured test message")
        self.assertEqual(doc["status"], 200)
        self.assertIn("timestamp", doc)


if __name__ == "__main__":
    unittest.main()
