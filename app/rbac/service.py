"""Authorization reads and role-assignment use cases shared by HTTP and the CLI."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.rbac import repository
from app.rbac.catalog import RoleName
from app.rbac.exceptions import (
    DefaultRoleMissingError,
    IneligibleAdministratorError,
    LastAdministratorError,
    PermissionDeniedError,
    RoleNotFoundError,
    UserNotFoundError,
)
from app.rbac.models import Role
from app.users import repository as user_repository
from app.users.models import User
from app.users.schemas import normalize_email

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PermissionInfo:
    key: str
    description: str


@dataclass(frozen=True, slots=True)
class RoleInfo:
    name: str
    description: str
    permissions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UserAccount:
    """Public account state. Assignment audit data is intentionally absent."""

    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UserPage:
    items: tuple[UserAccount, ...]
    total: int
    offset: int
    limit: int


@dataclass(frozen=True, slots=True)
class Authorization:
    """A user's roles and effective permissions, read from the database."""

    roles: tuple[str, ...]
    permissions: tuple[str, ...]

    def allows(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        if not self.allows(permission):
            raise PermissionDeniedError()


class RbacService:
    """Owns the transaction boundary for each role-management use case."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_permissions(self) -> list[PermissionInfo]:
        return [
            PermissionInfo(key=permission.key, description=permission.description)
            for permission in repository.list_permissions(self._session)
        ]

    def list_roles(self) -> list[RoleInfo]:
        return [
            RoleInfo(
                name=role.name,
                description=role.description,
                permissions=tuple(permission.key for permission in role.permissions),
            )
            for role in repository.list_roles(self._session)
        ]

    def list_users(self, *, offset: int, limit: int, email: str | None = None) -> UserPage:
        """Page through users, optionally filtered by a case-insensitive email substring."""
        search = normalize_email(email) if email is not None else None
        users, total = repository.list_users(
            self._session, offset=offset, limit=limit, email_search=search or None
        )
        return UserPage(
            items=tuple(_account(user) for user in users),
            total=total,
            offset=offset,
            limit=limit,
        )

    def get_user(self, user_id: UUID) -> UserAccount:
        user = repository.get_user_with_roles(self._session, user_id)
        if user is None:
            raise UserNotFoundError()
        return _account(user)

    def find_user_id(self, email: str) -> UUID:
        """Resolve an email address, normalized as at login, to a user ID."""
        user = user_repository.get_user_by_email(self._session, normalize_email(email))
        if user is None:
            raise UserNotFoundError()
        return user.id

    def get_authorization(self, user_id: UUID) -> Authorization:
        return Authorization(
            roles=tuple(repository.get_role_names(self._session, user_id)),
            permissions=tuple(repository.get_permission_keys(self._session, user_id)),
        )

    def assign_default_role(self, user_id: UUID) -> None:
        """Stage the ``user`` role for a new account. The caller commits.

        A missing seeded role is a configuration failure; the caller must roll
        back the whole account rather than commit it without a role.
        """
        role = repository.get_role_by_name(self._session, RoleName.USER)
        if role is None:
            logger.error("Seeded role %r is missing; run the database migrations", RoleName.USER)
            raise DefaultRoleMissingError()
        repository.add_user_role(
            self._session, user_id=user_id, role_id=role.id, assigned_by_user_id=None
        )

    def grant_role(
        self, user_id: UUID, role_name: str, *, assigned_by_user_id: UUID | None = None
    ) -> bool:
        """Idempotently assign a role. Returns whether the assignment was created.

        ``assigned_by_user_id`` is null for system and CLI assignments. Only
        active, verified accounts may receive ``admin``.
        """
        with self._rollback_on_error():
            user = self._require_user(user_id)
            role = self._require_role(role_name)
            if role.name == RoleName.ADMIN and not _is_eligible(user):
                raise IneligibleAdministratorError()

            created = repository.add_user_role(
                self._session,
                user_id=user.id,
                role_id=role.id,
                assigned_by_user_id=assigned_by_user_id,
            )
            self._session.commit()

        if created:
            logger.info("Role %s granted to user %s", role.name, user.id)
        return created

    def revoke_role(self, user_id: UUID, role_name: str) -> bool:
        """Idempotently remove a role. Returns whether an assignment was removed.

        Removing ``admin`` locks the admin role row first, so concurrent removals
        are serialized and each one counts the administrators the previous left.
        """
        with self._rollback_on_error():
            user = self._require_user(user_id)
            role = self._require_role(role_name)
            if role.name == RoleName.ADMIN:
                repository.lock_role(self._session, role.id)
                if (
                    _is_eligible(user)
                    and repository.has_user_role(self._session, user_id=user.id, role_id=role.id)
                    and repository.count_active_verified_users_with_role(self._session, role.id)
                    <= 1
                ):
                    raise LastAdministratorError()

            removed = repository.remove_user_role(self._session, user_id=user.id, role_id=role.id)
            self._session.commit()

        if removed:
            logger.info("Role %s removed from user %s", role.name, user.id)
        return removed

    @contextmanager
    def _rollback_on_error(self) -> Iterator[None]:
        """Discard partial work and release row locks when a use case fails."""
        try:
            yield
        except Exception:
            self._session.rollback()
            raise

    def _require_user(self, user_id: UUID) -> User:
        user = user_repository.get_user_by_id(self._session, user_id)
        if user is None:
            raise UserNotFoundError()
        return user

    def _require_role(self, name: str) -> Role:
        role = repository.get_role_by_name(self._session, name)
        if role is None:
            raise RoleNotFoundError()
        return role


def _is_eligible(user: User) -> bool:
    """Whether the account can act as an administrator."""
    return user.is_active and user.is_verified


def _account(user: User) -> UserAccount:
    return UserAccount(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
        roles=tuple(sorted(assignment.role.name for assignment in user.role_assignments)),
    )
