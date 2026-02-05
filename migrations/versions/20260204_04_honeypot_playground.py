"""Add honeypot playground storage tables."""

from alembic import op

revision = "20260204_04_honeypot_playground"
down_revision = "20240204_03_honeypot_checks_endpoint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS honeypot_jobs (
          job_id TEXT PRIMARY KEY,
          created_ts TEXT NOT NULL,
          updated_ts TEXT,
          actor_id TEXT,
          kind TEXT,
          status TEXT,
          payload_json TEXT
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS honeypot_files (
          file_id TEXT PRIMARY KEY,
          created_ts TEXT NOT NULL,
          actor_id TEXT,
          source_endpoint TEXT,
          filename TEXT,
          size INTEGER,
          md5 TEXT,
          sha1 TEXT,
          sha256 TEXT,
          mime TEXT,
          meta_json TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_hp_jobs_created ON honeypot_jobs(created_ts)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_hp_files_sha256 ON honeypot_files(sha256)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_hp_files_sha256")
    op.execute("DROP INDEX IF EXISTS idx_hp_jobs_created")
    op.execute("DROP TABLE IF EXISTS honeypot_files")
    op.execute("DROP TABLE IF EXISTS honeypot_jobs")
