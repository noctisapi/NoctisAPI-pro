"""Add signal-enriched columns to campaigns and campaign_actor_links."""

from alembic import op

revision = "20260316_01_campaigns_signals"
down_revision = "20260208_02_cases_campaigns_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # campaigns: extended metadata from 9-signal correlation
    op.execute("ALTER TABLE campaigns ADD COLUMN request_count INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE campaigns ADD COLUMN session_count INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE campaigns ADD COLUMN confidence_score REAL NOT NULL DEFAULT 0.0")
    op.execute("ALTER TABLE campaigns ADD COLUMN behavior_pattern TEXT")
    op.execute("ALTER TABLE campaigns ADD COLUMN ip_diversity INTEGER NOT NULL DEFAULT 0")

    # campaign_actor_links: per-signal score breakdown
    op.execute("ALTER TABLE campaign_actor_links ADD COLUMN signal_scores_json TEXT")


def downgrade() -> None:
    # SQLite does not support DROP COLUMN in older versions — no-op downgrade
    pass
