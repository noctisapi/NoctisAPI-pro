import sqlite3

from app import log_export_stream


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    log_export_stream.ensure_tables(conn)
    return conn


def test_export_event_includes_source_ip():
    conn = _conn()
    try:
        log_export_stream.try_emit_export_event(
            conn,
            kind="auth_login",
            method="POST",
            path="/auth/login",
            status=200,
            latency_ms=42,
            actor_id="act_test_123",
            source_ip="203.0.113.10",
            country="ES",
            trap_flags=["auth"],
        )
        conn.commit()

        events = log_export_stream.get_events_after(conn, 0, 10)
        assert len(events) == 1
        assert events[0]["data"]["source_ip"] == "203.0.113.10"
        assert events[0]["data"]["country"] == "ES"
    finally:
        conn.close()
