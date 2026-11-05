"""NOC-020: the membership-change audit trail.

Pure unit tests against app.panel_membership_audit, using an isolated
in-memory sqlite connection per test.
"""
from __future__ import annotations

import sqlite3
import unittest

from app import panel_membership_audit


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    panel_membership_audit.ensure_tables(conn)
    return conn


class TestMembershipAudit(unittest.TestCase):
    def setUp(self):
        self.conn = _conn()

    def tearDown(self):
        self.conn.close()

    def test_recorded_entry_is_listed(self):
        panel_membership_audit.record(
            self.conn, actor_username="olivia", action="invite", target_username="newbie", detail="role=viewer"
        )
        entries = panel_membership_audit.list_recent(self.conn)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["actor_username"], "olivia")
        self.assertEqual(entries[0]["action"], "invite")
        self.assertEqual(entries[0]["target_username"], "newbie")
        self.assertEqual(entries[0]["detail"], "role=viewer")
        self.assertTrue(entries[0]["created_at"])

    def test_most_recent_first(self):
        panel_membership_audit.record(self.conn, actor_username="a", action="create", target_username="x")
        panel_membership_audit.record(self.conn, actor_username="a", action="deactivate", target_username="y")
        entries = panel_membership_audit.list_recent(self.conn)
        self.assertEqual([e["target_username"] for e in entries], ["y", "x"])

    def test_limit_is_respected(self):
        for i in range(5):
            panel_membership_audit.record(self.conn, actor_username="a", action="create", target_username=f"u{i}")
        entries = panel_membership_audit.list_recent(self.conn, limit=2)
        self.assertEqual(len(entries), 2)

    def test_no_entries_returns_empty_list(self):
        self.assertEqual(panel_membership_audit.list_recent(self.conn), [])

    def test_cli_actor_constant(self):
        self.assertEqual(panel_membership_audit.CLI_ACTOR, "operator-cli")


if __name__ == "__main__":
    unittest.main()
