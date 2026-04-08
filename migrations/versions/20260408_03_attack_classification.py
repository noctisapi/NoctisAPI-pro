"""Add attack classification columns to cases, actors, and campaigns.

cases:
    attack_type          TEXT     — "automated" | "targeted" | NULL (unclassified)
    confidence_score     REAL     — 0.0–1.0, set at case creation
    analysis_signals_json TEXT    — JSON blob of per-signal scores

actors:
    typical_behavior     TEXT     — "automated" | "targeted" | "mixed" | NULL
                                    Populated by batch aggregation, not per-request.

campaigns:
    automated_ratio      REAL     — fraction of linked cases classified as automated
    targeted_ratio       REAL     — fraction of linked cases classified as targeted
"""

from alembic import op

revision = "20260408_03_attack_classification"
down_revision = "20260408_02_log_export_refresh_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Cases: immutable classification set at case creation time
    op.execute("ALTER TABLE cases ADD COLUMN attack_type TEXT")
    op.execute("ALTER TABLE cases ADD COLUMN confidence_score REAL NOT NULL DEFAULT 0.0")
    op.execute("ALTER TABLE cases ADD COLUMN analysis_signals_json TEXT")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_cases_attack_type ON cases(attack_type)"
    )

    # Actors: derived majority-vote field, updated by batch aggregation
    op.execute("ALTER TABLE actors ADD COLUMN typical_behavior TEXT")

    # Campaigns: ratio aggregates computed from linked case data (no classification here)
    op.execute("ALTER TABLE campaigns ADD COLUMN automated_ratio REAL NOT NULL DEFAULT 0.0")
    op.execute("ALTER TABLE campaigns ADD COLUMN targeted_ratio REAL NOT NULL DEFAULT 0.0")


def downgrade() -> None:
    # SQLite does not support DROP COLUMN — no-op downgrade (schema is forward-only)
    pass
