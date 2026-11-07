"""Store the provider resource reference separately from the tenant ID."""

from alembic import op

revision = "20261107_05_control_center_provider_refs"
down_revision = "20261107_04_control_center_worker_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE cc_deployments ADD COLUMN provider_ref TEXT")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_cc_deployments_provider_ref "
        "ON cc_deployments(provider, provider_ref) WHERE provider_ref IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ux_cc_deployments_provider_ref")
    op.execute("ALTER TABLE cc_deployments DROP COLUMN provider_ref")
