"""Add campaign_jobs table for background recompute metrics."""

from alembic import op

revision = "20260204_07_campaign_jobs"
down_revision = "20260204_06_restore_case_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS campaign_jobs (
          job_id TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          started_at TEXT,
          finished_at TEXT,
          duration_ms INTEGER,
          actors_considered INTEGER,
          features_cached INTEGER,
          features_built INTEGER,
          links_created INTEGER,
          cache_enabled INTEGER,
          params_json TEXT,
          error TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_campaign_jobs_status ON campaign_jobs(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_campaign_jobs_created ON campaign_jobs(created_at)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_campaign_jobs_created")
    op.execute("DROP INDEX IF EXISTS idx_campaign_jobs_status")
    op.execute("DROP TABLE IF EXISTS campaign_jobs")
