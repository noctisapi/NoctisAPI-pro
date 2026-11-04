"""Tests for app.honeypot_monitor's internal-monitor header handling.

NOC-012: the monitor must identify itself with the same real secret
app.honeypot_public._is_monitor() checks (constant-time compare against
HP_MONITOR_SECRET) -- never a hardcoded, guessable literal. A hardcoded
value would either do nothing (secret set to something else) or, worse,
become a predictable bypass if the operator's secret were ever weak.
"""
from __future__ import annotations

import importlib
import os
import sqlite3
import unittest


class TestBaseHeaders(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get("HP_MONITOR_SECRET")

    def tearDown(self):
        if self._old is None:
            os.environ.pop("HP_MONITOR_SECRET", None)
        else:
            os.environ["HP_MONITOR_SECRET"] = self._old

    def _monitor(self, module):
        return module.HoneypotAvailabilityMonitor(
            db_factory=lambda: sqlite3.connect(":memory:"),
            base_url="http://app:8000",
        )

    def test_no_secret_omits_header_entirely(self):
        os.environ.pop("HP_MONITOR_SECRET", None)
        import app.honeypot_monitor as honeypot_monitor
        module = importlib.reload(honeypot_monitor)
        headers = self._monitor(module)._base_headers()
        self.assertNotIn("X-Internal-Monitor", headers)

    def test_secret_set_sends_real_secret_not_a_literal(self):
        os.environ["HP_MONITOR_SECRET"] = "a-real-random-secret-value"
        import app.honeypot_monitor as honeypot_monitor
        module = importlib.reload(honeypot_monitor)
        headers = self._monitor(module)._base_headers()
        self.assertEqual(headers["X-Internal-Monitor"], "a-real-random-secret-value")
        self.assertNotEqual(headers["X-Internal-Monitor"], "1")


if __name__ == "__main__":
    unittest.main()
