"""Alembic migrations against a fresh, empty PostgreSQL database."""

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL, Connection
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.exc import IntegrityError, OperationalError

from app.core import database
from app.rbac.catalog import PermissionKey, RoleName

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUTH_TABLES = {"users", "refresh_tokens", "action_tokens"}
RBAC_TABLES = {"roles", "permissions", "role_permissions", "user_roles"}
APPLICATION_TABLES = AUTH_TABLES | RBAC_TABLES
PRE_RBAC_REVISION = "20261025_02"

SEEDED_ROLES = {
    (UUID("ddc99bc1-c68b-4cbb-91f8-ce94068cdd28"), "user", "Standard account access."),
    (UUID("43bb3892-6728-4cc3-92bd-12cd2d648114"), "admin", "Full administrative access."),
}
SEEDED_PERMISSIONS = {
    (
        UUID("1628fd02-40f5-49f2-bc99-2aa16b445785"),
        "profile:read",
        "Read the authenticated user's own profile.",
    ),
    (
        UUID("552c07ff-aaa1-4efd-8e37-b626cbf66760"),
        "users:read",
        "List and inspect users through the administration API.",
    ),
    (
        UUID("98390c5d-5e31-406d-ba60-f2453ee23a79"),
        "roles:read",
        "List the role and permission catalog.",
    ),
    (
        UUID("bcf9ee42-a8f9-4dd4-b21e-d032ff03647f"),
        "roles:assign",
        "Assign and remove roles from users.",
    ),
}
SEEDED_ROLE_PERMISSIONS = {
    ("user", "profile:read"),
    ("admin", "profile:read"),
    ("admin", "users:read"),
    ("admin", "roles:read"),
    ("admin", "roles:assign"),
}


@pytest.fixture
def empty_database() -> Iterator[URL]:
    """Create a uniquely named database for one test and drop it afterwards."""
    name = f"auth_migration_test_{uuid4().hex[:12]}"
    admin_url = database.engine.url.set(database="postgres")
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
    except OperationalError as error:
        admin.dispose()
        reason = str(error.orig).splitlines()[-1].strip()
        pytest.skip(f"PostgreSQL is unavailable for migration tests: {reason}")
    try:
        yield database.engine.url.set(database=name)
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def alembic(url: URL, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the Alembic CLI exactly as documented, against ``url``."""
    environment = {
        **os.environ,
        "AUTH_DATABASE_URL": url.render_as_string(hide_password=False),
    }
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    return completed


def test_initial_migrations_upgrade_check_and_downgrade_an_empty_database(
    empty_database: URL,
) -> None:
    engine = create_engine(empty_database)
    try:
        with engine.connect() as connection:
            assert inspect(connection).get_table_names() == []

        alembic(empty_database, "upgrade", "head")
        with engine.connect() as connection:
            schema = inspect(connection)
            assert set(schema.get_table_names()) == APPLICATION_TABLES | {"alembic_version"}
            assert_users_schema(schema)
            assert_token_schema(schema)
            assert_rbac_schema(schema)
            assert_rbac_seed(connection)
            enum_labels: set[str] = set(
                connection.execute(
                    text("select unnest(enum_range(null::action_token_purpose))::text")
                ).scalars()
            )
            assert enum_labels == {"email_verification", "password_reset"}

        # Models and migrations agree: autogenerate finds nothing to add.
        check = alembic(empty_database, "check")
        assert "No new upgrade operations detected" in check.stdout + check.stderr

        alembic(empty_database, "downgrade", "base")
        with engine.connect() as connection:
            assert set(inspect(connection).get_table_names()) == {"alembic_version"}
            remaining_enum: int = connection.execute(
                text("select count(*) from pg_type where typname = 'action_token_purpose'")
            ).scalar_one()
            assert remaining_enum == 0

        alembic(empty_database, "upgrade", "head")
        with engine.connect() as connection:
            assert APPLICATION_TABLES <= set(inspect(connection).get_table_names())
            assert_rbac_seed(connection)
    finally:
        engine.dispose()


def test_rbac_migration_backfills_existing_users_and_downgrades_without_losing_them(
    empty_database: URL,
) -> None:
    engine = create_engine(empty_database)
    try:
        alembic(empty_database, "upgrade", PRE_RBAC_REVISION)
        with engine.begin() as connection:
            user_ids = {
                insert_user(connection, f"existing-{index}@example.com") for index in range(3)
            }

        alembic(empty_database, "upgrade", "head")
        with engine.connect() as connection:
            assert_rbac_seed(connection)
            assert user_role_rows(connection) == {(user_id, "user", None) for user_id in user_ids}

        alembic(empty_database, "downgrade", PRE_RBAC_REVISION)
        with engine.connect() as connection:
            assert set(inspect(connection).get_table_names()) == AUTH_TABLES | {"alembic_version"}
            remaining: set[UUID] = set(connection.execute(text("select id from users")).scalars())
            assert remaining == user_ids

        # Re-upgrading backfills again from a clean slate, once per user.
        alembic(empty_database, "upgrade", "head")
        with engine.connect() as connection:
            assert_rbac_seed(connection)
            assert user_role_rows(connection) == {(user_id, "user", None) for user_id in user_ids}
    finally:
        engine.dispose()


def test_rbac_deletion_rules(empty_database: URL) -> None:
    engine = create_engine(empty_database)
    try:
        alembic(empty_database, "upgrade", "head")
        with engine.connect() as connection:
            member = insert_user(connection, "member@example.com")
            assigner = insert_user(connection, "assigner@example.com")
            admin_role = role_id(connection, "admin")
            connection.execute(
                text(
                    "insert into user_roles (user_id, role_id, assigned_by_user_id) "
                    "values (:user_id, :role_id, :assigner)"
                ),
                {"user_id": member, "role_id": admin_role, "assigner": assigner},
            )

            # Deleting the assigning user keeps the assignment but clears the audit actor.
            connection.execute(text("delete from users where id = :id"), {"id": assigner})
            assert (member, "admin", None) in user_role_rows(connection)

            # Deleting a user removes their assignments.
            connection.execute(text("delete from users where id = :id"), {"id": member})
            assert all(row[0] != member for row in user_role_rows(connection))

            # Deleting a permission removes its role mappings; deleting a role removes
            # its mappings and assignments.
            connection.execute(text("delete from permissions where key = 'users:read'"))
            assert ("admin", "users:read") not in role_permission_rows(connection)
            survivor = insert_user(connection, "survivor@example.com")
            connection.execute(
                text("insert into user_roles (user_id, role_id) values (:user_id, :role_id)"),
                {"user_id": survivor, "role_id": admin_role},
            )
            connection.execute(text("delete from roles where name = 'admin'"))
            assert all(role != "admin" for role, _ in role_permission_rows(connection))
            assert all(role != "admin" for _, role, _ in user_role_rows(connection))
            surviving_users: int = connection.execute(
                text("select count(*) from users where id = :id"), {"id": survivor}
            ).scalar_one()
            assert surviving_users == 1

            # Duplicate assignments and mappings are rejected by composite primary keys.
            assignment = {"user_id": survivor, "role_id": role_id(connection, "user")}
            insert_assignment = text(
                "insert into user_roles (user_id, role_id) values (:user_id, :role_id)"
            )
            connection.execute(insert_assignment, assignment)
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(insert_assignment, assignment)
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(
                    text(
                        "insert into role_permissions (role_id, permission_id) "
                        "select role_id, permission_id from role_permissions limit 1"
                    )
                )
            connection.rollback()
    finally:
        engine.dispose()


def test_catalog_constants_match_seeded_values() -> None:
    assert {role.value for role in RoleName} == {name for _, name, _ in SEEDED_ROLES}
    assert {permission.value for permission in PermissionKey} == {
        key for _, key, _ in SEEDED_PERMISSIONS
    }


def insert_user(connection: Connection, email: str) -> UUID:
    user_id = uuid4()
    connection.execute(
        text("insert into users (id, email, hashed_password) values (:id, :email, 'hash')"),
        {"id": user_id, "email": email},
    )
    return user_id


def role_id(connection: Connection, name: str) -> UUID:
    value: UUID = connection.execute(
        text("select id from roles where name = :name"), {"name": name}
    ).scalar_one()
    return value


def user_role_rows(connection: Connection) -> set[tuple[UUID, str, UUID | None]]:
    rows = connection.execute(
        text(
            "select user_roles.user_id, roles.name, user_roles.assigned_by_user_id "
            "from user_roles join roles on roles.id = user_roles.role_id"
        )
    )
    return {(row[0], row[1], row[2]) for row in rows}


def role_permission_rows(connection: Connection) -> set[tuple[str, str]]:
    rows = connection.execute(
        text(
            "select roles.name, permissions.key from role_permissions "
            "join roles on roles.id = role_permissions.role_id "
            "join permissions on permissions.id = role_permissions.permission_id"
        )
    )
    return {(row[0], row[1]) for row in rows}


def assert_rbac_seed(connection: Connection) -> None:
    roles = {
        (row[0], row[1], row[2])
        for row in connection.execute(text("select id, name, description from roles"))
    }
    assert roles == SEEDED_ROLES
    permissions = {
        (row[0], row[1], row[2])
        for row in connection.execute(text("select id, key, description from permissions"))
    }
    assert permissions == SEEDED_PERMISSIONS
    assert role_permission_rows(connection) == SEEDED_ROLE_PERMISSIONS


def assert_users_schema(schema: Inspector) -> None:
    columns = {column["name"]: column for column in schema.get_columns("users")}
    assert set(columns) == {
        "id",
        "email",
        "hashed_password",
        "is_active",
        "is_verified",
        "created_at",
        "updated_at",
    }
    assert all(not column["nullable"] for column in columns.values())
    assert columns["created_at"]["type"].timezone is True  # type: ignore[attr-defined]

    unique_columns = {
        tuple(constraint["column_names"]) for constraint in schema.get_unique_constraints("users")
    }
    assert ("email",) in unique_columns
    indexes = {index["name"]: index for index in schema.get_indexes("users")}
    assert indexes["uq_users_email_lower"]["unique"] is True


def assert_token_schema(schema: Inspector) -> None:
    for table in ("refresh_tokens", "action_tokens"):
        unique_columns = {
            tuple(constraint["column_names"]) for constraint in schema.get_unique_constraints(table)
        }
        assert ("token_hash",) in unique_columns
        user_keys = [
            key for key in schema.get_foreign_keys(table) if key["referred_table"] == "users"
        ]
        assert [key["options"].get("ondelete") for key in user_keys] == ["CASCADE"]
        indexed = {tuple(index["column_names"]) for index in schema.get_indexes(table)}
        assert {("user_id",), ("expires_at",)} <= indexed

    refresh_indexes = {
        tuple(index["column_names"]) for index in schema.get_indexes("refresh_tokens")
    }
    assert ("family_id",) in refresh_indexes
    self_reference = [
        key
        for key in schema.get_foreign_keys("refresh_tokens")
        if key["referred_table"] == "refresh_tokens"
    ]
    assert [key["options"].get("ondelete") for key in self_reference] == ["SET NULL"]


def assert_rbac_schema(schema: Inspector) -> None:
    for table, column in (("roles", "name"), ("permissions", "key")):
        columns = {item["name"]: item for item in schema.get_columns(table)}
        assert set(columns) == {"id", column, "description", "created_at", "updated_at"}
        assert all(not item["nullable"] for item in columns.values())
        assert schema.get_pk_constraint(table)["constrained_columns"] == ["id"]
        unique_columns = {
            tuple(constraint["column_names"]) for constraint in schema.get_unique_constraints(table)
        }
        assert (column,) in unique_columns

    assert schema.get_pk_constraint("role_permissions")["constrained_columns"] == [
        "role_id",
        "permission_id",
    ]
    assert foreign_keys(schema, "role_permissions") == {
        ("role_id", "roles", "CASCADE"),
        ("permission_id", "permissions", "CASCADE"),
    }
    assert ("permission_id",) in index_columns(schema, "role_permissions")

    columns = {item["name"]: item for item in schema.get_columns("user_roles")}
    assert set(columns) == {"user_id", "role_id", "assigned_at", "assigned_by_user_id"}
    assert columns["assigned_by_user_id"]["nullable"] is True
    assert not columns["assigned_at"]["nullable"]
    assert columns["assigned_at"]["type"].timezone is True  # type: ignore[attr-defined]
    assert schema.get_pk_constraint("user_roles")["constrained_columns"] == ["user_id", "role_id"]
    assert foreign_keys(schema, "user_roles") == {
        ("user_id", "users", "CASCADE"),
        ("role_id", "roles", "CASCADE"),
        ("assigned_by_user_id", "users", "SET NULL"),
    }
    assert {("role_id",), ("assigned_by_user_id",)} <= index_columns(schema, "user_roles")


def foreign_keys(schema: Inspector, table: str) -> set[tuple[str, str, str | None]]:
    return {
        (key["constrained_columns"][0], key["referred_table"], key["options"].get("ondelete"))
        for key in schema.get_foreign_keys(table)
    }


def index_columns(schema: Inspector, table: str) -> set[tuple[str | None, ...]]:
    return {tuple(index["column_names"]) for index in schema.get_indexes(table)}
