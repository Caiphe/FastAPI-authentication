"""Enforce case-insensitive email uniqueness.

Revision ID: 20261025_02
Revises: 20261025_01
Create Date: 2026-10-25
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20261025_02"
down_revision: str | None = "20261025_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add a unique index on the lower-cased email address."""
    op.create_index(
        "uq_users_email_lower",
        "users",
        [sa.literal_column("lower(email)")],
        unique=True,
    )


def downgrade() -> None:
    """Remove the case-insensitive email index."""
    op.drop_index("uq_users_email_lower", table_name="users")
