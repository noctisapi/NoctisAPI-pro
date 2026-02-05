"""Restore case_evidence table and triggers (shim for missing revision)."""

from alembic import op

revision = "20260204_05_restore_case_evidence"
down_revision = "20260204_05_remove_case_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS case_evidence (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id INTEGER NOT NULL,
          ref_type TEXT NOT NULL,
          ref_id TEXT NOT NULL,
          note TEXT,
          added_at TEXT NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_public_protect_session_case BEFORE DELETE ON sessions
        BEGIN
            SELECT CASE
                WHEN EXISTS (SELECT 1 FROM case_evidence WHERE ref_type='session' AND ref_id=OLD.session_id)
                THEN RAISE(ABORT, 'session linked to case evidence')
            END;
        END;
        """
    )
    op.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_public_protect_step_case BEFORE DELETE ON session_steps
        BEGIN
            SELECT CASE
                WHEN EXISTS (SELECT 1 FROM case_evidence WHERE ref_type='step' AND ref_id=CAST(OLD.id AS TEXT))
                THEN RAISE(ABORT, 'step linked to case evidence')
            END;
        END;
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_public_protect_step_case")
    op.execute("DROP TRIGGER IF EXISTS trg_public_protect_session_case")
    op.execute("DROP TABLE IF EXISTS case_evidence")
