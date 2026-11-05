"""Add panel_membership_audit table (NOC-020)."""

from alembic import op

revision = "20261105_03_panel_membership_audit"
down_revision = "20261105_02_panel_users_role"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS panel_membership_audit (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at      TEXT NOT NULL,
            actor_username  TEXT NOT NULL,
            action          TEXT NOT NULL,
            target_username TEXT NOT NULL,
            detail          TEXT
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_panel_membership_audit_created_at ON panel_membership_audit(created_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_panel_membership_audit_created_at")
    op.execute("DROP TABLE IF EXISTS panel_membership_audit")
