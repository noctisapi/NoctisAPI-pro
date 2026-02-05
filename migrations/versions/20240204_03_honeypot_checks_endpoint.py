"""Add endpoint column to honeypot checks."""

from alembic import op

# revision identifiers, used by Alembic.
revision = "20240204_03_honeypot_checks_endpoint"
down_revision = "20240204_02_honeypot_checks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE honeypot_checks ADD COLUMN endpoint TEXT NOT NULL DEFAULT '/health'")
    op.execute("CREATE INDEX IF NOT EXISTS idx_honeypot_checks_endpoint_ts ON honeypot_checks(endpoint, ts)")


def downgrade() -> None:
    # SQLite cannot drop columns easily; rebuild table if necessary.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS honeypot_checks_tmp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ok INTEGER NOT NULL,
            status_code INTEGER,
            latency_ms INTEGER,
            error TEXT
        )
        """
    )
    op.execute(
        """
        INSERT INTO honeypot_checks_tmp (id, ts, ok, status_code, latency_ms, error)
        SELECT id, ts, ok, status_code, latency_ms, error FROM honeypot_checks
        """
    )
    op.execute("DROP TABLE honeypot_checks")
    op.execute("ALTER TABLE honeypot_checks_tmp RENAME TO honeypot_checks")
