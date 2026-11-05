"""Add role column to panel_users (NOC-019: owner/admin/analyst/viewer)."""

from alembic import op

revision = "20261105_02_panel_users_role"
down_revision = "20261105_01_panel_users_sessions"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    rows = bind.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in rows)


def upgrade() -> None:
    # Default to the least-privileged role for any pre-existing row -- an
    # operator explicitly promotes accounts afterward (scripts/panel_user.py
    # set-role). New accounts created via that CLI default to 'owner'
    # instead, at the application layer, not here.
    if not _has_column("panel_users", "role"):
        op.execute("ALTER TABLE panel_users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'")


def downgrade() -> None:
    # SQLite does not support DROP COLUMN -- no-op downgrade (schema is forward-only)
    pass
