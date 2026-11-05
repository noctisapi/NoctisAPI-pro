"""Add panel_users, panel_sessions, panel_password_resets tables (NOC-018)."""

from alembic import op

revision = "20261105_01_panel_users_sessions"
down_revision = "20260408_03_attack_classification"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS panel_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT    NOT NULL,
            last_login_at TEXT
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS panel_sessions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            token_hash   TEXT    NOT NULL UNIQUE,
            created_at   TEXT    NOT NULL,
            expires_at   TEXT    NOT NULL,
            revoked_at   TEXT,
            last_seen_at TEXT,
            ip_address   TEXT,
            user_agent   TEXT
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_panel_sessions_user_id ON panel_sessions(user_id)"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS panel_password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token_hash TEXT    NOT NULL UNIQUE,
            created_at TEXT    NOT NULL,
            expires_at TEXT    NOT NULL,
            used_at    TEXT
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_panel_password_resets_user_id ON panel_password_resets(user_id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_panel_password_resets_user_id")
    op.execute("DROP TABLE IF EXISTS panel_password_resets")
    op.execute("DROP INDEX IF EXISTS ix_panel_sessions_user_id")
    op.execute("DROP TABLE IF EXISTS panel_sessions")
    op.execute("DROP TABLE IF EXISTS panel_users")
