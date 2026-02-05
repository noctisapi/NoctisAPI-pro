"""Initial database schema for Honey App."""

from alembic import op

revision = "20240203_01_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS actors (
      actor_id TEXT PRIMARY KEY,
      first_seen TEXT NOT NULL,
      last_seen  TEXT NOT NULL,
      score      INTEGER NOT NULL DEFAULT 0,
      err_total  INTEGER NOT NULL DEFAULT 0,
      err_consecutive INTEGER NOT NULL DEFAULT 0,
      last_status INTEGER,
      last_error_ts TEXT,
      lifecycle_state TEXT DEFAULT 'active',
      is_archived INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      path TEXT,
      method TEXT,
      ip TEXT,
      ua TEXT,
      status INTEGER,
      body_sample TEXT,
      token TEXT,
      extra_json TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id TEXT NOT NULL,
      token TEXT NOT NULL,
      created_ts TEXT NOT NULL,
      stage INTEGER NOT NULL DEFAULT 0,
      gift_type TEXT NOT NULL DEFAULT 'standard',
      used_count INTEGER NOT NULL DEFAULT 0,
      last_used_ts TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS issued_secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      value TEXT NOT NULL,
      created_ts TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT,
      tags TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS case_actors (
      case_id INTEGER NOT NULL,
      actor_id TEXT NOT NULL,
      added_at TEXT NOT NULL,
      role TEXT,
      PRIMARY KEY(case_id, actor_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS case_evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL,
      ref_type TEXT NOT NULL,
      ref_id TEXT NOT NULL,
      note TEXT,
      added_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      stage_max INTEGER,
      summary TEXT,
      fingerprint TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS session_steps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      seq INTEGER NOT NULL,
      ts TEXT NOT NULL,
      method TEXT,
      path TEXT,
      query_json TEXT,
      headers_json TEXT,
      body_json TEXT,
      response_status INTEGER,
      response_json TEXT,
      stage_before INTEGER,
      stage_after INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS campaigns (
      campaign_id TEXT PRIMARY KEY,
      label TEXT,
      created_at TEXT NOT NULL,
      last_seen_at TEXT,
      score_avg REAL,
      features_summary_json TEXT,
      representative_session_id TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_actor_links (
      campaign_id TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      confidence REAL,
      reasons_json TEXT,
      linked_at TEXT NOT NULL,
      PRIMARY KEY(campaign_id, actor_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_fingerprints (
      actor_id TEXT PRIMARY KEY,
      fp_json TEXT,
      updated_at TEXT
    )
    """,
]

INDEX_STATEMENTS = [
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_issued_actor_kind ON issued_secrets(actor_id, kind)",
    "CREATE INDEX IF NOT EXISTS idx_issued_value ON issued_secrets(value)",
    "CREATE INDEX IF NOT EXISTS idx_events_actor_id ON events(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_path ON events(path)",
    "CREATE INDEX IF NOT EXISTS idx_tokens_actor_id ON tokens(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token)",
    "CREATE INDEX IF NOT EXISTS idx_actors_score ON actors(score)",
    "CREATE INDEX IF NOT EXISTS idx_actors_last_seen ON actors(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_actor_id ON sessions(actor_id)",
    "CREATE INDEX IF NOT EXISTS idx_session_steps_session_id ON session_steps(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)",
]

TRIGGER_STATEMENTS = [
    """
    CREATE TRIGGER IF NOT EXISTS trg_public_protect_session_case BEFORE DELETE ON sessions
    BEGIN
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM case_evidence WHERE ref_type='session' AND ref_id=OLD.session_id)
            THEN RAISE(ABORT, 'session linked to case evidence')
        END;
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_public_protect_step_case BEFORE DELETE ON session_steps
    BEGIN
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM case_evidence WHERE ref_type='step' AND ref_id=CAST(OLD.id AS TEXT))
            THEN RAISE(ABORT, 'step linked to case evidence')
        END;
    END;
    """,
]


def upgrade() -> None:
    for statement in SCHEMA_STATEMENTS + INDEX_STATEMENTS + TRIGGER_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP TRIGGER IF EXISTS trg_public_protect_step_case",
        "DROP TRIGGER IF EXISTS trg_public_protect_session_case",
        "DROP TABLE IF EXISTS campaign_actor_links",
        "DROP TABLE IF EXISTS campaigns",
        "DROP TABLE IF EXISTS session_steps",
        "DROP TABLE IF EXISTS sessions",
        "DROP TABLE IF EXISTS case_evidence",
        "DROP TABLE IF EXISTS case_actors",
        "DROP TABLE IF EXISTS cases",
        "DROP TABLE IF EXISTS issued_secrets",
        "DROP TABLE IF EXISTS tokens",
        "DROP TABLE IF EXISTS events",
        "DROP TABLE IF EXISTS actor_fingerprints",
        "DROP TABLE IF EXISTS actors"
    ):
        op.execute(statement)