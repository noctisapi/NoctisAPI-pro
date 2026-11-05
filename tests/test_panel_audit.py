"""NOC-021: the general administrative audit log.

Pure unit tests against app.panel_audit, using an isolated in-memory
sqlite connection per test.
"""
from __future__ import annotations

import sqlite3
import unittest

from app import panel_audit


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    panel_audit.ensure_tables(conn)
    return conn


class TestShouldRecord(unittest.TestCase):
    def test_get_with_success_is_not_recorded(self):
        self.assertFalse(panel_audit.should_record("GET", 200))

    def test_get_with_403_is_recorded(self):
        self.assertTrue(panel_audit.should_record("GET", 403))

    def test_post_is_always_recorded_regardless_of_status(self):
        self.assertTrue(panel_audit.should_record("POST", 200))
        self.assertTrue(panel_audit.should_record("POST", 400))
        self.assertTrue(panel_audit.should_record("POST", 500))

    def test_delete_is_recorded(self):
        self.assertTrue(panel_audit.should_record("DELETE", 200))

    def test_method_case_is_irrelevant(self):
        self.assertFalse(panel_audit.should_record("get", 200))
        self.assertTrue(panel_audit.should_record("post", 200))

    def test_missing_status_on_a_get_is_not_recorded(self):
        self.assertFalse(panel_audit.should_record("GET", None))


class TestRecordAndList(unittest.TestCase):
    def setUp(self):
        self.conn = _conn()

    def tearDown(self):
        self.conn.close()

    def test_recorded_entry_round_trips(self):
        panel_audit.record(
            self.conn,
            request_id="abc123",
            actor_username="olivia",
            actor_role="owner",
            method="post",
            path="/dashboard/environment/settings",
            status_code=400,
        )
        entries = panel_audit.list_recent(self.conn)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["request_id"], "abc123")
        self.assertEqual(e["actor_username"], "olivia")
        self.assertEqual(e["actor_role"], "owner")
        self.assertEqual(e["method"], "POST")  # normalized uppercase
        self.assertEqual(e["path"], "/dashboard/environment/settings")
        self.assertEqual(e["status_code"], 400)
        self.assertTrue(e["created_at"])

    def test_anonymous_actor_is_allowed(self):
        panel_audit.record(
            self.conn,
            request_id="x",
            actor_username=None,
            actor_role=None,
            method="POST",
            path="/dashboard/members/invite",
            status_code=403,
        )
        entries = panel_audit.list_recent(self.conn)
        self.assertIsNone(entries[0]["actor_username"])

    def test_most_recent_first(self):
        panel_audit.record(
            self.conn, request_id="1", actor_username="a", actor_role="admin",
            method="POST", path="/x", status_code=200,
        )
        panel_audit.record(
            self.conn, request_id="2", actor_username="a", actor_role="admin",
            method="POST", path="/y", status_code=200,
        )
        entries = panel_audit.list_recent(self.conn)
        self.assertEqual([e["path"] for e in entries], ["/y", "/x"])

    def test_failures_only_filters_by_status(self):
        panel_audit.record(
            self.conn, request_id="1", actor_username="a", actor_role="admin",
            method="POST", path="/ok", status_code=200,
        )
        panel_audit.record(
            self.conn, request_id="2", actor_username="a", actor_role="viewer",
            method="GET", path="/denied", status_code=403,
        )
        all_entries = panel_audit.list_recent(self.conn)
        failures = panel_audit.list_recent(self.conn, failures_only=True)
        self.assertEqual(len(all_entries), 2)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["path"], "/denied")

    def test_limit_is_respected(self):
        for i in range(5):
            panel_audit.record(
                self.conn, request_id=str(i), actor_username="a", actor_role="admin",
                method="POST", path=f"/p{i}", status_code=200,
            )
        self.assertEqual(len(panel_audit.list_recent(self.conn, limit=2)), 2)


if __name__ == "__main__":
    unittest.main()
