"""Add refresh-token support to log export consumers."""

from alembic import op

revision = "20260408_02_log_export_refresh_tokens"
down_revision = "20260408_01_log_export_stream"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    rows = bind.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in rows)


def _add_column_if_missing(table: str, column: str, ddl_type: str) -> None:
    if not _has_column(table, column):
        op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")


def upgrade() -> None:
    _add_column_if_missing("log_stream_consumers", "access_token_hash", "TEXT")
    _add_column_if_missing("log_stream_consumers", "access_token_expires_at", "TEXT")
    _add_column_if_missing("log_stream_consumers", "refresh_token_hash", "TEXT")
    _add_column_if_missing("log_stream_consumers", "refresh_token_expires_at", "TEXT")
    _add_column_if_missing("log_stream_consumers", "refresh_token_rotated_at", "TEXT")
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_log_stream_consumers_access_token_hash
        ON log_stream_consumers(access_token_hash)
        WHERE access_token_hash IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_log_stream_consumers_refresh_token_hash
        ON log_stream_consumers(refresh_token_hash)
        WHERE refresh_token_hash IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ux_log_stream_consumers_refresh_token_hash")
    op.execute("DROP INDEX IF EXISTS ux_log_stream_consumers_access_token_hash")

