"""Alembic migrations against a fresh, empty PostgreSQL database."""

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.exc import OperationalError

from app.core import database

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APPLICATION_TABLES = {"users", "refresh_tokens", "action_tokens"}


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
    finally:
        engine.dispose()


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
