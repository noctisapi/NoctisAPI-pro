"""Add log_export_stream tables: system_secrets, log_stream_consumers, export_events."""

from alembic import op

revision = "20260408_01_log_export_stream"
down_revision = "20260316_01_campaigns_signals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # General-purpose encrypted secrets store.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS system_secrets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL UNIQUE,
            encrypted_value TEXT    NOT NULL,
            created_at      TEXT    NOT NULL,
            updated_at      TEXT    NOT NULL
        )
        """
    )

    # Authorised log-stream consumers (one row per API consumer token).
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS log_stream_consumers (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL,
            token_hash   TEXT    NOT NULL UNIQUE,
            enabled      INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT    NOT NULL,
            last_used_at TEXT,
            last_used_ip TEXT,
            expires_at   TEXT
        )
        """
    )

    # Export-safe event records.  cursor (= rowid) is monotonically increasing.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS export_events (
            cursor       INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id     TEXT NOT NULL UNIQUE,
            created_at   TEXT NOT NULL,
            event_type   TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            instance_id  TEXT NOT NULL
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_export_events_created_at ON export_events(created_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_export_events_created_at")
    op.execute("DROP TABLE IF EXISTS export_events")
    op.execute("DROP TABLE IF EXISTS log_stream_consumers")
    op.execute("DROP TABLE IF EXISTS system_secrets")
