"""Add billing event and customer cost control tables (NOC-052/053)."""

from alembic import op

revision = "20261106_03_control_center_billing_costs"
down_revision = "20261106_02_control_center_customers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_subscription_events (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            subscription_id    INTEGER NOT NULL,
            external_event_id  TEXT NOT NULL UNIQUE,
            provider           TEXT NOT NULL,
            event_type         TEXT NOT NULL,
            applied_state      TEXT,
            reconciliation_state TEXT NOT NULL DEFAULT 'pending'
                               CHECK (reconciliation_state IN ('pending', 'applied', 'failed')),
            received_at        TEXT NOT NULL,
            details_json       TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY (subscription_id) REFERENCES cc_subscriptions(id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_cost_budgets (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id    INTEGER NOT NULL,
            period_start   TEXT NOT NULL,
            period_end     TEXT NOT NULL,
            budget_cents   INTEGER NOT NULL CHECK (budget_cents >= 0),
            warning_pct    INTEGER NOT NULL DEFAULT 80 CHECK (warning_pct BETWEEN 1 AND 100),
            critical_pct   INTEGER NOT NULL DEFAULT 100 CHECK (critical_pct BETWEEN 1 AND 100),
            created_at     TEXT NOT NULL,
            UNIQUE (customer_id, period_start, period_end),
            FOREIGN KEY (customer_id) REFERENCES cc_customers(id) ON DELETE CASCADE
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_subscription_events_subscription_id ON cc_subscription_events(subscription_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_subscription_events_reconciliation ON cc_subscription_events(reconciliation_state)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_cost_budgets_customer_period ON cc_cost_budgets(customer_id, period_start, period_end)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cc_cost_budgets_customer_period")
    op.execute("DROP INDEX IF EXISTS ix_cc_subscription_events_reconciliation")
    op.execute("DROP INDEX IF EXISTS ix_cc_subscription_events_subscription_id")
    op.execute("DROP TABLE IF EXISTS cc_cost_budgets")
    op.execute("DROP TABLE IF EXISTS cc_subscription_events")
