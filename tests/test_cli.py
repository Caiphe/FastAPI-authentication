"""Role-management CLI: parsing, outcomes, exit codes, and safe error output."""

import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app import cli
from app.core import database
from app.rbac import repository
from app.rbac.catalog import RoleName
from app.rbac.models import UserRole
from app.users.models import User
from tests.conftest import assignment, make_user

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run(
    capsys: pytest.CaptureFixture[str], session: Session | None, *argv: str
) -> tuple[int, str, str]:
    def factory() -> AbstractContextManager[Session]:
        assert session is not None
        return nullcontext(session)

    code = cli.main(list(argv), session_factory=factory)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture
def no_other_admins(db_session: Session) -> None:
    admin = repository.get_role_by_name(db_session, RoleName.ADMIN)
    assert admin is not None
    db_session.execute(delete(UserRole).where(UserRole.role_id == admin.id))
    db_session.commit()


# Parsing and validation (exit 2)


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["promote", "--email", "a@example.com", "--role", "admin"],
        ["grant-role", "--role", "admin"],
        ["grant-role", "--email", "a@example.com"],
        ["revoke-role", "--email", "a@example.com"],
    ],
    ids=["no-command", "unknown-command", "missing-email", "missing-role", "revoke-missing-role"],
)
def test_parse_errors_exit_2(capsys: pytest.CaptureFixture[str], argv: list[str]) -> None:
    code, out, err = run(capsys, None, *argv)

    assert code == 2
    assert out == ""
    assert "usage:" in err


@pytest.mark.parametrize("email", ["not-an-email", "   ", "a@b@example.com"])
def test_invalid_email_exits_2_without_touching_the_database(
    capsys: pytest.CaptureFixture[str], email: str
) -> None:
    code, out, err = run(capsys, None, "grant-role", "--email", email, "--role", "admin")

    assert code == 2
    assert out == ""
    assert err == "error: --email must be a valid email address\n"


def test_help_lists_both_commands(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, None, "--help")

    assert code == 0
    assert "grant-role" in out and "revoke-role" in out


# Grants and revocations (exit 0)


@pytest.mark.integration
def test_grant_normalizes_email_and_records_no_actor(
    capsys: pytest.CaptureFixture[str], db_session: Session
) -> None:
    user = make_user(db_session)

    code, out, err = run(
        capsys, db_session, "grant-role", "--email", f"  {user.email.upper()} ", "--role", "admin"
    )

    assert (code, err) == (0, "")
    assert out == f"Granted role 'admin' to {user.email}.\n"
    granted = assignment(db_session, user.id, "admin")
    assert granted is not None and granted.assigned_by_user_id is None


@pytest.mark.integration
def test_grant_is_idempotent(capsys: pytest.CaptureFixture[str], db_session: Session) -> None:
    user = make_user(db_session, roles=(RoleName.USER,))

    code, out, _ = run(capsys, db_session, "grant-role", "--email", user.email, "--role", "user")

    assert code == 0
    assert out == f"{user.email} already has role 'user'; nothing changed.\n"


@pytest.mark.integration
def test_revoke_and_repeat_revoke(capsys: pytest.CaptureFixture[str], db_session: Session) -> None:
    user = make_user(db_session, roles=(RoleName.USER,))
    argv = ("revoke-role", "--email", user.email, "--role", "user")

    code, out, _ = run(capsys, db_session, *argv)
    assert (code, out) == (0, f"Removed role 'user' from {user.email}.\n")
    assert assignment(db_session, user.id, "user") is None

    code, out, _ = run(capsys, db_session, *argv)
    assert (code, out) == (0, f"{user.email} does not have role 'user'; nothing changed.\n")


# Not found (exit 3)


@pytest.mark.integration
@pytest.mark.parametrize("command", ["grant-role", "revoke-role"])
def test_unknown_user_exits_3(
    capsys: pytest.CaptureFixture[str], db_session: Session, command: str
) -> None:
    email = f"missing-{uuid4().hex}@example.com"

    code, out, err = run(capsys, db_session, command, "--email", email, "--role", "user")

    assert (code, out) == (3, "")
    assert err == "error: The user does not exist.\n"


@pytest.mark.integration
@pytest.mark.parametrize("command", ["grant-role", "revoke-role"])
def test_unknown_role_exits_3(
    capsys: pytest.CaptureFixture[str], db_session: Session, command: str
) -> None:
    user = make_user(db_session)

    code, out, err = run(capsys, db_session, command, "--email", user.email, "--role", "root")

    assert (code, out) == (3, "")
    assert err == "error: The role does not exist.\n"


# Business-rule conflicts (exit 4)


@pytest.mark.integration
@pytest.mark.parametrize(("is_active", "is_verified"), [(False, True), (True, False)])
def test_ineligible_admin_grant_exits_4(
    capsys: pytest.CaptureFixture[str], db_session: Session, is_active: bool, is_verified: bool
) -> None:
    user = make_user(db_session, is_active=is_active, is_verified=is_verified)
    db_session.commit()

    code, out, err = run(capsys, db_session, "grant-role", "--email", user.email, "--role", "admin")

    assert (code, out) == (4, "")
    assert err == "error: The admin role can only be granted to an active, verified account.\n"
    assert assignment(db_session, user.id, "admin") is None


@pytest.mark.integration
@pytest.mark.usefixtures("no_other_admins")
def test_last_admin_revoke_exits_4(capsys: pytest.CaptureFixture[str], db_session: Session) -> None:
    user = make_user(db_session, roles=(RoleName.ADMIN,))
    db_session.commit()

    code, out, err = run(
        capsys, db_session, "revoke-role", "--email", user.email, "--role", "admin"
    )

    assert (code, out) == (4, "")
    assert err.startswith("error: The admin role cannot be removed from the last")
    assert assignment(db_session, user.id, "admin") is not None


# Unexpected failures (exit 1)


@pytest.mark.integration
def test_failed_write_rolls_back_and_exits_1(
    capsys: pytest.CaptureFixture[str], db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = make_user(db_session)
    db_session.commit()
    real_add = repository.add_user_role

    def add_then_fail(session: Session, **kwargs: UUID | None) -> bool:
        real_add(session, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("disk full at /var/lib/postgresql")

    monkeypatch.setattr(repository, "add_user_role", add_then_fail)

    code, out, err = run(capsys, db_session, "grant-role", "--email", user.email, "--role", "user")

    assert (code, out) == (1, "")
    assert err == "error: the operation failed unexpectedly (RuntimeError); it is safe to retry\n"
    assert assignment(db_session, user.id, "user") is None


def test_database_errors_are_reported_without_secrets(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_url = "postgresql://auth:hunter2@db.internal:5432/auth"

    def unavailable() -> AbstractContextManager[Session]:
        raise OperationalError(f"connect to {secret_url}", {"password": "hunter2"}, Exception())

    code = cli.main(
        ["grant-role", "--email", "a@example.com", "--role", "admin"],
        session_factory=unavailable,
    )
    captured = capsys.readouterr()

    assert code == 1
    assert captured.out == ""
    assert captured.err == (
        "error: the operation failed unexpectedly (OperationalError); it is safe to retry\n"
    )
    for leaked in ("hunter2", "db.internal", "postgresql://", "Traceback"):
        assert leaked not in captured.err


# Real process against the configured database


@pytest.fixture
def committed_verified_user() -> Iterator[User]:
    email = f"cli-{uuid4().hex}@example.com"
    try:
        with database.SessionFactory() as session:
            user = make_user(session, email)
            session.commit()
    except OperationalError as error:
        reason = str(error.orig).splitlines()[-1].strip()
        pytest.skip(f"PostgreSQL is unavailable for integration tests: {reason}")
    try:
        yield user
    finally:
        with database.SessionFactory() as session:
            session.execute(delete(User).where(User.email == email))
            session.commit()


def run_module(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "app.cli", *argv],
        cwd=PROJECT_ROOT,
        # Point the child at the same database as the tests' engine.
        env={
            **os.environ,
            "AUTH_DATABASE_URL": database.engine.url.render_as_string(hide_password=False),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_module_help_runs() -> None:
    completed = run_module("--help")

    assert completed.returncode == 0, completed.stderr
    assert "grant-role" in completed.stdout and "revoke-role" in completed.stdout


@pytest.mark.integration
def test_module_grants_admin_against_the_configured_database(
    committed_verified_user: User,
) -> None:
    email = committed_verified_user.email

    completed = run_module("grant-role", "--email", email.upper(), "--role", "admin")

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == f"Granted role 'admin' to {email}.\n"
    with database.SessionFactory() as session:
        assert repository.get_role_names(session, committed_verified_user.id) == ["admin"]

    repeated = run_module("grant-role", "--email", email, "--role", "admin")
    assert repeated.returncode == 0
    assert "nothing changed" in repeated.stdout


def test_module_rejects_bad_arguments() -> None:
    completed = run_module("grant-role", "--email", "nope", "--role", "admin")

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == "error: --email must be a valid email address\n"
