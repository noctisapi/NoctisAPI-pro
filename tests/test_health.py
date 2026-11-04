"""Tests for app.health — liveness, readiness, and version functions.

Covers:
 - liveness(): always returns {"status": "ok"}, no I/O
 - readiness():
     * healthy DB with initialised schema → status ok
     * missing DB file → status degraded
     * DB exists but alembic_version table missing → status degraded
     * latency_ms key is always present
 - version_info():
     * reads APP_VERSION, HP_API_VERSION, APP_ENV, BUILD_SHA, BUILD_TIME
     * APP_VERSION takes priority over HP_API_VERSION
     * all fields present even when env vars are unset (empty string)
     * no trailing/leading whitespace in values
 - Response speed: all pure functions complete well within 50 ms
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
import unittest

from app.health import liveness, readiness, version_info


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


class _EnvOverride:
    _VARS = ("APP_VERSION", "HP_API_VERSION", "APP_ENV", "BUILD_SHA", "BUILD_TIME")

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


def _make_db(with_schema: bool = True) -> str:
    """Create a temporary SQLite file, optionally with the alembic_version table."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    if with_schema:
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
        conn.execute("INSERT INTO alembic_version VALUES ('abc123')")
        conn.commit()
        conn.close()
    return path


# ---------------------------------------------------------------------------
# liveness()
# ---------------------------------------------------------------------------


class TestLiveness(unittest.TestCase):

    def test_returns_ok_status(self):
        result = liveness()
        self.assertEqual(result["status"], "ok")

    def test_returns_dict(self):
        self.assertIsInstance(liveness(), dict)

    def test_no_io_is_fast(self):
        t0 = time.perf_counter()
        for _ in range(1000):
            liveness()
        elapsed_ms = (time.perf_counter() - t0) * 1000
        # 1000 calls in <50 ms is very conservative — typically <1 ms total
        self.assertLess(elapsed_ms, 50)

    def test_always_returns_same_shape(self):
        for _ in range(5):
            result = liveness()
            self.assertIn("status", result)
            self.assertEqual(result["status"], "ok")


# ---------------------------------------------------------------------------
# readiness()
# ---------------------------------------------------------------------------


class TestReadiness(unittest.TestCase):

    def test_healthy_db_with_schema(self):
        path = _make_db(with_schema=True)
        try:
            result = readiness(path)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["checks"]["database"], "ok")
        finally:
            os.unlink(path)

    def test_missing_db_file_is_degraded(self):
        result = readiness("/nonexistent/path/db.sqlite")
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["checks"]["database"], "error")

    def test_db_without_alembic_table_is_degraded(self):
        path = _make_db(with_schema=False)
        try:
            result = readiness(path)
            self.assertEqual(result["status"], "degraded")
            self.assertEqual(result["checks"]["database"], "error")
        finally:
            os.unlink(path)

    def test_latency_ms_always_present(self):
        path = _make_db()
        try:
            result = readiness(path)
            self.assertIn("latency_ms", result)
            self.assertIsInstance(result["latency_ms"], int)
            self.assertGreaterEqual(result["latency_ms"], 0)
        finally:
            os.unlink(path)

    def test_latency_ms_present_on_error(self):
        result = readiness("/nonexistent.db")
        self.assertIn("latency_ms", result)

    def test_error_name_present_on_db_failure(self):
        result = readiness("/nonexistent.db")
        self.assertIn("database_error", result["checks"])
        self.assertIsInstance(result["checks"]["database_error"], str)
        self.assertTrue(result["checks"]["database_error"])  # non-empty

    def test_no_error_key_on_success(self):
        path = _make_db()
        try:
            result = readiness(path)
            self.assertNotIn("database_error", result["checks"])
        finally:
            os.unlink(path)

    def test_checks_key_always_present(self):
        result = readiness("/nonexistent.db")
        self.assertIn("checks", result)
        self.assertIn("database", result["checks"])

    def test_completes_within_50ms_on_healthy_db(self):
        path = _make_db()
        try:
            t0 = time.perf_counter()
            readiness(path)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self.assertLess(elapsed_ms, 50)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# version_info()
# ---------------------------------------------------------------------------


class TestVersionInfo(unittest.TestCase):

    def test_all_fields_present_when_vars_set(self):
        with _EnvOverride(
            APP_VERSION="1.2.3",
            APP_ENV="prod",
            BUILD_SHA="abc1234",
            BUILD_TIME="2026-03-04T12:00:00Z",
        ):
            result = version_info()
        self.assertEqual(result["version"], "1.2.3")
        self.assertEqual(result["env"], "prod")
        self.assertEqual(result["build_sha"], "abc1234")
        self.assertEqual(result["build_time"], "2026-03-04T12:00:00Z")

    def test_all_fields_empty_when_vars_unset(self):
        with _EnvOverride():
            result = version_info()
        self.assertEqual(result["version"], "")
        self.assertEqual(result["env"], "")
        self.assertEqual(result["build_sha"], "")
        self.assertEqual(result["build_time"], "")

    def test_app_version_takes_priority_over_hp_api_version(self):
        with _EnvOverride(APP_VERSION="2.0.0", HP_API_VERSION="1.0.0"):
            result = version_info()
        self.assertEqual(result["version"], "2.0.0")

    def test_hp_api_version_used_when_app_version_unset(self):
        with _EnvOverride(HP_API_VERSION="1.5.0"):
            result = version_info()
        self.assertEqual(result["version"], "1.5.0")

    def test_whitespace_stripped_from_values(self):
        with _EnvOverride(APP_VERSION="  1.0.0  ", APP_ENV="  dev  "):
            result = version_info()
        self.assertEqual(result["version"], "1.0.0")
        self.assertEqual(result["env"], "dev")

    def test_returns_dict(self):
        with _EnvOverride():
            self.assertIsInstance(version_info(), dict)

    def test_required_keys_always_present(self):
        with _EnvOverride():
            result = version_info()
        for key in ("version", "env", "build_sha", "build_time"):
            self.assertIn(key, result)

    def test_no_io_is_fast(self):
        with _EnvOverride(APP_VERSION="1.0.0"):
            t0 = time.perf_counter()
            for _ in range(1000):
                version_info()
            elapsed_ms = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed_ms, 50)


if __name__ == "__main__":
    unittest.main()
