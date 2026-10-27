"""Create role-based access control tables and seed the catalog.

Revision ID: 20261027_01
Revises: 20261025_02
Create Date: 2026-10-27
"""

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa

from alembic import op

revision: str = "20261027_01"
down_revision: str | None = "20261025_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Seed values are frozen here rather than imported so this revision never changes
# behaviour when application code does. Future catalog changes need new revisions.
USER_ROLE_ID = UUID("ddc99bc1-c68b-4cbb-91f8-ce94068cdd28")
ADMIN_ROLE_ID = UUID("43bb3892-6728-4cc3-92bd-12cd2d648114")

ROLES = [
    {"id": USER_ROLE_ID, "name": "user", "description": "Standard account access."},
    {"id": ADMIN_ROLE_ID, "name": "admin", "description": "Full administrative access."},
]

PERMISSIONS = [
    {
        "id": UUID("1628fd02-40f5-49f2-bc99-2aa16b445785"),
        "key": "profile:read",
        "description": "Read the authenticated user's own profile.",
    },
    {
        "id": UUID("552c07ff-aaa1-4efd-8e37-b626cbf66760"),
        "key": "users:read",
        "description": "List and inspect users through the administration API.",
    },
    {
        "id": UUID("98390c5d-5e31-406d-ba60-f2453ee23a79"),
        "key": "roles:read",
        "description": "List the role and permission catalog.",
    },
    {
        "id": UUID("bcf9ee42-a8f9-4dd4-b21e-d032ff03647f"),
        "key": "roles:assign",
        "description": "Assign and remove roles from users.",
    },
]

ROLE_PERMISSION_KEYS = {
    USER_ROLE_ID: ["profile:read"],
    ADMIN_ROLE_ID: [permission["key"] for permission in PERMISSIONS],
}


def upgrade() -> None:
    """Create RBAC tables, seed roles and permissions, and grant existing users ``user``."""
    roles = op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name=op.f("uq_roles_name")),
    )

    permissions = op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_permissions")),
        sa.UniqueConstraint("key", name=op.f("uq_permissions_key")),
    )

    role_permissions = op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name=op.f("fk_role_permissions_permission_id_permissions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name=op.f("pk_role_permissions")),
    )
    op.create_index(
        "ix_role_permissions_permission_id",
        "role_permissions",
        ["permission_id"],
    )

    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("assigned_by_user_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["assigned_by_user_id"],
            ["users.id"],
            name=op.f("fk_user_roles_assigned_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_user_roles_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_roles_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name=op.f("pk_user_roles")),
    )
    op.create_index(
        "ix_user_roles_role_id",
        "user_roles",
        ["role_id"],
    )
    op.create_index(
        "ix_user_roles_assigned_by_user_id",
        "user_roles",
        ["assigned_by_user_id"],
    )

    op.bulk_insert(roles, ROLES)
    op.bulk_insert(permissions, PERMISSIONS)
    permission_ids = {permission["key"]: permission["id"] for permission in PERMISSIONS}
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": role_id, "permission_id": permission_ids[key]}
            for role_id, keys in ROLE_PERMISSION_KEYS.items()
            for key in keys
        ],
    )

    op.get_bind().execute(
        sa.text(
            "INSERT INTO user_roles (user_id, role_id) "
            "SELECT id, :role_id FROM users "
            "ON CONFLICT (user_id, role_id) DO NOTHING"
        ),
        {"role_id": USER_ROLE_ID},
    )


def downgrade() -> None:
    """Remove RBAC tables and data; users are left untouched."""
    op.drop_index("ix_user_roles_assigned_by_user_id", table_name="user_roles")
    op.drop_index("ix_user_roles_role_id", table_name="user_roles")
    op.drop_table("user_roles")

    op.drop_index("ix_role_permissions_permission_id", table_name="role_permissions")
    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
