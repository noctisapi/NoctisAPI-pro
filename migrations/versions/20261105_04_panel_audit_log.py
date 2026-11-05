"""Add panel_audit_log table (NOC-021)."""

from alembic import op

revision = "20261105_04_panel_audit_log"
down_revision = "20261105_03_panel_membership_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS panel_audit_log (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at     TEXT NOT NULL,
            request_id     TEXT NOT NULL,
            actor_username TEXT,
            actor_role     TEXT,
            method         TEXT NOT NULL,
            path           TEXT NOT NULL,
            status_code    INTEGER
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_panel_audit_log_created_at ON panel_audit_log(created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_panel_audit_log_status_code ON panel_audit_log(status_code)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_panel_audit_log_status_code")
    op.execute("DROP INDEX IF EXISTS ix_panel_audit_log_created_at")
    op.execute("DROP TABLE IF EXISTS panel_audit_log")
