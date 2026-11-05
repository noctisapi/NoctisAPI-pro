"""
Alembic revision template.
"""
revision =
down_revision =
branch_labels =
depends_on =

# NOC-029: set irreversible = True (and irreversible_reason = "...") only
# if downgrade() cannot actually restore data that upgrade() deletes or
# mutates -- see migrations/README.
# irreversible = True
# irreversible_reason = ""

from alembic import op
import sqlalchemy as sa


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass