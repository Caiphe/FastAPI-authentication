"""Command-line role management, used to bootstrap the first administrator.

Usage::

    python -m app.cli grant-role --email admin@example.com --role admin
    python -m app.cli revoke-role --email admin@example.com --role admin

Exit codes: 0 success (including no change needed), 1 unexpected failure,
2 invalid arguments, 3 unknown user or role, 4 refused by a business rule.
"""

import argparse
import sys
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

SessionFactory = Callable[[], AbstractContextManager["Session"]]

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_CONFLICT = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Manage user role assignments.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")
    for name, summary in (
        ("grant-role", "Assign a role to a user."),
        ("revoke-role", "Remove a role from a user."),
    ):
        command = commands.add_parser(name, help=summary, description=summary)
        command.add_argument("--email", required=True, help="The account's email address.")
        command.add_argument("--role", required=True, help="The role name, e.g. admin.")
    return parser


def main(
    argv: Sequence[str] | None = None, *, session_factory: SessionFactory | None = None
) -> int:
    """Run one command and return its exit code."""
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exit_request:  # argparse reports usage errors and --help this way
        return EXIT_OK if exit_request.code in (None, 0) else EXIT_USAGE

    email = _valid_email(args.email)
    if email is None:
        print("error: --email must be a valid email address", file=sys.stderr)
        return EXIT_USAGE

    try:
        return _run(args.command, email, args.role, session_factory)
    except Exception as error:
        # Exception text can include connection URLs or SQL; report only its type.
        # A failed commit leaves the outcome unknown, but both commands are idempotent.
        print(
            f"error: the operation failed unexpectedly ({type(error).__name__}); "
            "it is safe to retry",
            file=sys.stderr,
        )
        return EXIT_UNEXPECTED


def _valid_email(value: str) -> str | None:
    from pydantic import TypeAdapter, ValidationError

    from app.users.schemas import NormalizedEmail

    try:
        email: str = TypeAdapter(NormalizedEmail).validate_python(value)
    except ValidationError:
        return None
    return email


def _run(command: str, email: str, role: str, session_factory: SessionFactory | None) -> int:
    # Imported here so configuration errors are reported like any other failure.
    import app.models  # noqa: F401  Register every mapper before querying.
    from app.core.database import SessionFactory as DefaultSessionFactory
    from app.rbac.exceptions import (
        IneligibleAdministratorError,
        LastAdministratorError,
        RoleNotFoundError,
        UserNotFoundError,
    )
    from app.rbac.service import RbacService

    factory = session_factory or DefaultSessionFactory
    try:
        with factory() as session:
            service = RbacService(session)
            user_id = service.find_user_id(email)
            if command == "grant-role":
                # CLI assignments have no acting user.
                changed = service.grant_role(user_id, role, assigned_by_user_id=None)
                message = (
                    f"Granted role '{role}' to {email}."
                    if changed
                    else f"{email} already has role '{role}'; nothing changed."
                )
            else:
                changed = service.revoke_role(user_id, role)
                message = (
                    f"Removed role '{role}' from {email}."
                    if changed
                    else f"{email} does not have role '{role}'; nothing changed."
                )
    except (UserNotFoundError, RoleNotFoundError) as error:
        print(f"error: {error.message}", file=sys.stderr)
        return EXIT_NOT_FOUND
    except (IneligibleAdministratorError, LastAdministratorError) as error:
        print(f"error: {error.message}", file=sys.stderr)
        return EXIT_CONFLICT

    print(message)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
