"""Enhance cases/campaigns intelligence fields for PRO."""

from alembic import op

revision = "20260208_02_cases_campaigns_intel"
down_revision = "20260204_07_campaign_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Cases: intelligence/cache fields + optional campaign link
    op.execute("ALTER TABLE cases ADD COLUMN campaign_id TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE cases ADD COLUMN techniques_json TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN endpoints_json TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN stage_flow_json TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN timeline_start TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN timeline_end TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN similarity_json TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN last_intel_ts TEXT")
    op.execute("CREATE INDEX IF NOT EXISTS idx_cases_campaign_id ON cases(campaign_id)")

    # Case evidence: richer metadata for requests/payloads/headers
    op.execute("ALTER TABLE case_evidence ADD COLUMN evidence_json TEXT")
    op.execute("ALTER TABLE case_evidence ADD COLUMN source_path TEXT")
    op.execute("ALTER TABLE case_evidence ADD COLUMN source_method TEXT")
    op.execute("ALTER TABLE case_evidence ADD COLUMN source_stage INTEGER")
    op.execute("ALTER TABLE case_evidence ADD COLUMN source_status INTEGER")
    op.execute("ALTER TABLE case_evidence ADD COLUMN actor_id TEXT")

    # Campaigns: timeline + scoring + intel summary fields
    op.execute("ALTER TABLE campaigns ADD COLUMN first_seen_at TEXT")
    op.execute("ALTER TABLE campaigns ADD COLUMN score_det INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE campaigns ADD COLUMN activity_json TEXT")
    op.execute("ALTER TABLE campaigns ADD COLUMN timeline_json TEXT")
    op.execute("ALTER TABLE campaigns ADD COLUMN stage_flow_json TEXT")
    op.execute("ALTER TABLE campaigns ADD COLUMN techniques_json TEXT")
    op.execute("ALTER TABLE campaigns ADD COLUMN endpoints_json TEXT")


def downgrade() -> None:
    # SQLite does not support DROP COLUMN. Keep schema forward-only.
    pass
