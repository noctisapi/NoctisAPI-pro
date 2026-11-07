"""Create the isolated Control Center model (NOC-046)."""

from alembic import op

revision = "20261106_01_control_center"
down_revision = "20261105_04_panel_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # These tables intentionally contain customer/deployment metadata only.
    # Honeypot requests, attack events, panel users, and sessions stay in
    # their existing bounded contexts.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_customers (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            external_id    TEXT NOT NULL UNIQUE,
            legal_name     TEXT NOT NULL,
            status         TEXT NOT NULL DEFAULT 'active'
                           CHECK (status IN ('active', 'suspended', 'terminated')),
            billing_ref    TEXT,
            notes          TEXT,
            created_at     TEXT NOT NULL,
            updated_at     TEXT NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_subscriptions (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id         INTEGER NOT NULL,
            external_id         TEXT NOT NULL UNIQUE,
            plan_code           TEXT NOT NULL,
            commercial_state    TEXT NOT NULL DEFAULT 'pending'
                                CHECK (commercial_state IN
                                  ('pending', 'active', 'past_due', 'suspended', 'terminated')),
            mode                TEXT NOT NULL CHECK (mode IN ('managed', 'self_hosted')),
            entitlement_version INTEGER NOT NULL DEFAULT 1 CHECK (entitlement_version > 0),
            starts_at           TEXT,
            ends_at             TEXT,
            billing_ref         TEXT,
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES cc_customers(id) ON DELETE RESTRICT
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_deployments (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id     INTEGER NOT NULL,
            subscription_id INTEGER,
            external_id     TEXT NOT NULL UNIQUE,
            tenant_id       TEXT NOT NULL UNIQUE,
            provider        TEXT NOT NULL,
            region          TEXT NOT NULL,
            state           TEXT NOT NULL DEFAULT 'pending'
                            CHECK (state IN
                              ('pending', 'provisioning', 'active', 'stale', 'suspended', 'terminated')),
            version_id      INTEGER,
            last_seen_at    TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES cc_customers(id) ON DELETE RESTRICT,
            FOREIGN KEY (subscription_id) REFERENCES cc_subscriptions(id) ON DELETE SET NULL,
            FOREIGN KEY (version_id) REFERENCES cc_versions(id) ON DELETE SET NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_domains (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            deployment_id   INTEGER NOT NULL,
            hostname        TEXT NOT NULL UNIQUE,
            kind            TEXT NOT NULL CHECK (kind IN ('api', 'console', 'other')),
            provider        TEXT,
            tunnel_ref      TEXT,
            state           TEXT NOT NULL DEFAULT 'pending'
                            CHECK (state IN ('pending', 'active', 'stale', 'disabled')),
            last_verified_at TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            FOREIGN KEY (deployment_id) REFERENCES cc_deployments(id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_jobs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            deployment_id   INTEGER NOT NULL,
            job_type        TEXT NOT NULL CHECK (job_type IN
                              ('deploy', 'status', 'verify', 'upgrade', 'backup',
                               'suspend', 'teardown', 'reconcile')),
            state           TEXT NOT NULL DEFAULT 'queued'
                            CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
            idempotency_key TEXT NOT NULL UNIQUE,
            requested_by    TEXT NOT NULL,
            parameters_json TEXT NOT NULL DEFAULT '{}',
            progress        INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
            error_code      TEXT,
            error_message   TEXT,
            created_at      TEXT NOT NULL,
            started_at      TEXT,
            completed_at    TEXT,
            FOREIGN KEY (deployment_id) REFERENCES cc_deployments(id) ON DELETE RESTRICT
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_versions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            version     TEXT NOT NULL UNIQUE,
            channel     TEXT NOT NULL DEFAULT 'stable'
                        CHECK (channel IN ('stable', 'beta', 'nightly')),
            image_ref   TEXT,
            release_ref TEXT,
            created_at  TEXT NOT NULL,
            is_active   INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_infra_costs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            deployment_id  INTEGER NOT NULL,
            provider       TEXT NOT NULL,
            period_start   TEXT NOT NULL,
            period_end     TEXT NOT NULL,
            amount_cents   INTEGER NOT NULL CHECK (amount_cents >= 0),
            currency       TEXT NOT NULL DEFAULT 'EUR',
            estimate_source TEXT NOT NULL,
            captured_at    TEXT NOT NULL,
            FOREIGN KEY (deployment_id) REFERENCES cc_deployments(id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_ref   TEXT NOT NULL,
            action      TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id   TEXT NOT NULL,
            request_id  TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at  TEXT NOT NULL
        )
        """
    )

    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_subscriptions_customer_id ON cc_subscriptions(customer_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_deployments_customer_id ON cc_deployments(customer_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_deployments_state ON cc_deployments(state)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_domains_deployment_id ON cc_domains(deployment_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_jobs_deployment_state ON cc_jobs(deployment_id, state)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_infra_costs_deployment_period ON cc_infra_costs(deployment_id, period_start)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_audit_log_entity ON cc_audit_log(entity_type, entity_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cc_audit_log_entity")
    op.execute("DROP INDEX IF EXISTS ix_cc_infra_costs_deployment_period")
    op.execute("DROP INDEX IF EXISTS ix_cc_jobs_deployment_state")
    op.execute("DROP INDEX IF EXISTS ix_cc_domains_deployment_id")
    op.execute("DROP INDEX IF EXISTS ix_cc_deployments_state")
    op.execute("DROP INDEX IF EXISTS ix_cc_deployments_customer_id")
    op.execute("DROP INDEX IF EXISTS ix_cc_subscriptions_customer_id")
    op.execute("DROP TABLE IF EXISTS cc_audit_log")
    op.execute("DROP TABLE IF EXISTS cc_infra_costs")
    op.execute("DROP TABLE IF EXISTS cc_jobs")
    op.execute("DROP TABLE IF EXISTS cc_domains")
    op.execute("DROP TABLE IF EXISTS cc_deployments")
    op.execute("DROP TABLE IF EXISTS cc_subscriptions")
    op.execute("DROP TABLE IF EXISTS cc_customers")
