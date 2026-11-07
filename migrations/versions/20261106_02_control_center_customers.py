"""Add customer contract data for the Control Center (NOC-048)."""

from alembic import op

revision = "20261106_02_control_center_customers"
down_revision = "20261106_01_control_center"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_customer_contacts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id  INTEGER NOT NULL,
            name         TEXT NOT NULL,
            email        TEXT NOT NULL,
            role         TEXT,
            phone        TEXT,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES cc_customers(id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_contracts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id   INTEGER NOT NULL,
            external_id   TEXT NOT NULL UNIQUE,
            contract_code TEXT NOT NULL,
            plan_code     TEXT NOT NULL,
            state         TEXT NOT NULL DEFAULT 'active'
                          CHECK (state IN ('draft', 'active', 'expired', 'terminated')),
            starts_at     TEXT NOT NULL,
            ends_at       TEXT,
            notes         TEXT,
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES cc_customers(id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS cc_customer_authorizations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id  INTEGER NOT NULL,
            subject_ref  TEXT NOT NULL,
            role         TEXT NOT NULL,
            scope_json   TEXT NOT NULL DEFAULT '{}',
            is_active    INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            UNIQUE (customer_id, subject_ref),
            FOREIGN KEY (customer_id) REFERENCES cc_customers(id) ON DELETE CASCADE
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_customer_contacts_customer_id ON cc_customer_contacts(customer_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_contracts_customer_id ON cc_contracts(customer_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cc_customer_auth_customer_id ON cc_customer_authorizations(customer_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cc_customer_auth_customer_id")
    op.execute("DROP INDEX IF EXISTS ix_cc_contracts_customer_id")
    op.execute("DROP INDEX IF EXISTS ix_cc_customer_contacts_customer_id")
    op.execute("DROP TABLE IF EXISTS cc_customer_authorizations")
    op.execute("DROP TABLE IF EXISTS cc_contracts")
    op.execute("DROP TABLE IF EXISTS cc_customer_contacts")
