"""Add honeypot availability checks table."""

from alembic import op

# revision identifiers, used by Alembic.
revision = "20240204_02_honeypot_checks"
down_revision = "20240203_01_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS honeypot_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ok INTEGER NOT NULL,
            status_code INTEGER,
            latency_ms INTEGER,
            error TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_honeypot_checks_ts ON honeypot_checks(ts)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_honeypot_checks_ok_ts ON honeypot_checks(ok, ts)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS honeypot_checks")
