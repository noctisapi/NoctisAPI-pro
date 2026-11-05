"""NOC-018: individual panel user identity and DB-backed revocable sessions.

Pure unit tests against app.panel_auth, using an isolated in-memory sqlite
connection per test -- no FastAPI, no network, no mocking of the module
under test.
"""
from __future__ import annotations

import sqlite3
import time
import unittest

from app import panel_auth


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    panel_auth.ensure_tables(conn)
    return conn


class TestPasswordHashing(unittest.TestCase):
    def test_correct_password_verifies(self):
        stored = panel_auth.hash_password("correct-horse-battery-staple")
        self.assertTrue(panel_auth.verify_password("correct-horse-battery-staple", stored))

    def test_wrong_password_rejected(self):
        stored = panel_auth.hash_password("correct-horse-battery-staple")
        self.assertFalse(panel_auth.verify_password("wrong-password", stored))

    def test_same_password_hashes_differ_by_salt(self):
        a = panel_auth.hash_password("same-password-both-times")
        b = panel_auth.hash_password("same-password-both-times")
        self.assertNotEqual(a, b)
        self.assertTrue(panel_auth.verify_password("same-password-both-times", a))
        self.assertTrue(panel_auth.verify_password("same-password-both-times", b))

    def test_malformed_stored_hash_is_rejected_not_raised(self):
        self.assertFalse(panel_auth.verify_password("anything", "not-a-valid-hash"))


class TestUsers(unittest.TestCase):
    def setUp(self):
        self.conn = _conn()

    def tearDown(self):
        self.conn.close()

    def test_create_and_fetch_user(self):
        user_id = panel_auth.create_user(self.conn, "alice", "a-long-enough-password")
        row = panel_auth.get_user_by_username(self.conn, "alice")
        self.assertEqual(row["id"], user_id)
        self.assertEqual(row["username"], "alice")
        self.assertTrue(row["is_active"])

    def test_duplicate_username_rejected(self):
        panel_auth.create_user(self.conn, "bob", "password-one")
        with self.assertRaises(panel_auth.UsernameTakenError):
            panel_auth.create_user(self.conn, "bob", "password-two")

    def test_unknown_username_returns_none(self):
        self.assertIsNone(panel_auth.get_user_by_username(self.conn, "nobody"))

    def test_deactivating_user_revokes_their_sessions(self):
        user_id = panel_auth.create_user(self.conn, "carol", "a-long-enough-password")
        token = panel_auth.create_session(self.conn, user_id)
        self.assertIsNotNone(panel_auth.verify_session(self.conn, token))
        panel_auth.set_user_active(self.conn, user_id, False)
        self.assertIsNone(panel_auth.verify_session(self.conn, token))

    def test_update_password_changes_verification(self):
        user_id = panel_auth.create_user(self.conn, "dave", "old-password-12345")
        panel_auth.update_password(self.conn, user_id, "new-password-67890")
        row = panel_auth.get_user_by_id(self.conn, user_id)
        self.assertFalse(panel_auth.verify_password("old-password-12345", row["password_hash"]))
        self.assertTrue(panel_auth.verify_password("new-password-67890", row["password_hash"]))


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.conn = _conn()
        self.user_id = panel_auth.create_user(self.conn, "erin", "a-long-enough-password")

    def tearDown(self):
        self.conn.close()

    def test_valid_session_resolves_to_owning_user(self):
        token = panel_auth.create_session(self.conn, self.user_id)
        row = panel_auth.verify_session(self.conn, token)
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], self.user_id)
        self.assertEqual(row["username"], "erin")

    def test_unknown_token_rejected(self):
        self.assertIsNone(panel_auth.verify_session(self.conn, "not-a-real-token"))

    def test_empty_token_rejected(self):
        self.assertIsNone(panel_auth.verify_session(self.conn, ""))

    def test_revoked_session_rejected(self):
        token = panel_auth.create_session(self.conn, self.user_id)
        panel_auth.revoke_session(self.conn, token)
        self.assertIsNone(panel_auth.verify_session(self.conn, token))

    def test_expired_session_rejected(self):
        token = panel_auth.create_session(self.conn, self.user_id, ttl_seconds=1)
        self.conn.execute(
            "UPDATE panel_sessions SET expires_at = '2000-01-01T00:00:00Z' WHERE token_hash = ?",
            (panel_auth._hash_token(token),),
        )
        self.conn.commit()
        self.assertIsNone(panel_auth.verify_session(self.conn, token))

    def test_revoke_all_sessions_for_user_kills_every_session(self):
        t1 = panel_auth.create_session(self.conn, self.user_id)
        t2 = panel_auth.create_session(self.conn, self.user_id)
        panel_auth.revoke_all_sessions_for_user(self.conn, self.user_id)
        self.assertIsNone(panel_auth.verify_session(self.conn, t1))
        self.assertIsNone(panel_auth.verify_session(self.conn, t2))

    def test_sessions_are_independent_per_user(self):
        other_id = panel_auth.create_user(self.conn, "frank", "another-long-password")
        mine = panel_auth.create_session(self.conn, self.user_id)
        panel_auth.revoke_all_sessions_for_user(self.conn, other_id)
        self.assertIsNotNone(panel_auth.verify_session(self.conn, mine))

    def test_verify_session_updates_last_seen(self):
        token = panel_auth.create_session(self.conn, self.user_id)
        row = self.conn.execute(
            "SELECT last_seen_at FROM panel_sessions WHERE token_hash = ?",
            (panel_auth._hash_token(token),),
        ).fetchone()
        first_seen = row["last_seen_at"]
        time.sleep(1.1)
        panel_auth.verify_session(self.conn, token)
        row2 = self.conn.execute(
            "SELECT last_seen_at FROM panel_sessions WHERE token_hash = ?",
            (panel_auth._hash_token(token),),
        ).fetchone()
        self.assertNotEqual(first_seen, row2["last_seen_at"])


class TestPasswordReset(unittest.TestCase):
    def setUp(self):
        self.conn = _conn()
        self.user_id = panel_auth.create_user(self.conn, "grace", "original-password-123")

    def tearDown(self):
        self.conn.close()

    def test_valid_reset_token_changes_password(self):
        token = panel_auth.create_password_reset(self.conn, self.user_id)
        ok = panel_auth.consume_password_reset(self.conn, token, "brand-new-password-456")
        self.assertTrue(ok)
        row = panel_auth.get_user_by_id(self.conn, self.user_id)
        self.assertTrue(panel_auth.verify_password("brand-new-password-456", row["password_hash"]))

    def test_reset_token_is_single_use(self):
        token = panel_auth.create_password_reset(self.conn, self.user_id)
        self.assertTrue(panel_auth.consume_password_reset(self.conn, token, "first-new-password-1"))
        self.assertFalse(panel_auth.consume_password_reset(self.conn, token, "second-new-password-2"))

    def test_unknown_reset_token_rejected(self):
        self.assertFalse(panel_auth.consume_password_reset(self.conn, "bogus-token", "whatever-password-1"))

    def test_expired_reset_token_rejected(self):
        token = panel_auth.create_password_reset(self.conn, self.user_id)
        self.conn.execute(
            "UPDATE panel_password_resets SET expires_at = '2000-01-01T00:00:00Z' WHERE token_hash = ?",
            (panel_auth._hash_token(token),),
        )
        self.conn.commit()
        self.assertFalse(panel_auth.consume_password_reset(self.conn, token, "whatever-password-2"))

    def test_successful_reset_revokes_existing_sessions(self):
        session_token = panel_auth.create_session(self.conn, self.user_id)
        reset_token = panel_auth.create_password_reset(self.conn, self.user_id)
        panel_auth.consume_password_reset(self.conn, reset_token, "post-reset-password-789")
        self.assertIsNone(panel_auth.verify_session(self.conn, session_token))


class TestCsrf(unittest.TestCase):
    def test_same_session_token_yields_same_csrf_token(self):
        a = panel_auth.derive_csrf_token("session-token-abc")
        b = panel_auth.derive_csrf_token("session-token-abc")
        self.assertEqual(a, b)

    def test_different_session_tokens_yield_different_csrf_tokens(self):
        a = panel_auth.derive_csrf_token("session-token-abc")
        b = panel_auth.derive_csrf_token("session-token-xyz")
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
