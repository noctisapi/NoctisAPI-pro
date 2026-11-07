"""Add leases and bounded retries to Control Center jobs."""

from alembic import op

revision = "20261107_04_control_center_worker_leases"
down_revision = "20261106_03_control_center_billing_costs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE cc_jobs ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0)")
    op.execute("ALTER TABLE cc_jobs ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10)")
    op.execute("ALTER TABLE cc_jobs ADD COLUMN lease_token TEXT")
    op.execute("ALTER TABLE cc_jobs ADD COLUMN lease_expires_at TEXT")
    op.execute("ALTER TABLE cc_jobs ADD COLUMN heartbeat_at TEXT")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_cc_jobs_worker_queue "
        "ON cc_jobs(state, job_type, lease_expires_at, id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cc_jobs_worker_queue")
    op.execute("ALTER TABLE cc_jobs DROP COLUMN heartbeat_at")
    op.execute("ALTER TABLE cc_jobs DROP COLUMN lease_expires_at")
    op.execute("ALTER TABLE cc_jobs DROP COLUMN lease_token")
    op.execute("ALTER TABLE cc_jobs DROP COLUMN max_attempts")
    op.execute("ALTER TABLE cc_jobs DROP COLUMN attempt_count")
