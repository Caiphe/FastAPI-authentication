"""Persistence operations for roles, permissions, and role assignments."""

from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, selectinload

from app.rbac.models import Permission, Role, UserRole, role_permissions
from app.users.models import User

# Assignments are changed with bulk statements, so user loads refresh any
# collections already in the session rather than trusting them.
_WITH_ROLES = selectinload(User.role_assignments).joinedload(UserRole.role)


def list_permissions(session: Session) -> list[Permission]:
    return list(session.scalars(select(Permission).order_by(Permission.key)))


def list_roles(session: Session) -> list[Role]:
    """Load every role with its permissions, ordered by name and key."""
    statement = select(Role).options(selectinload(Role.permissions)).order_by(Role.name)
    return list(session.scalars(statement))


def get_role_by_name(session: Session, name: str) -> Role | None:
    return session.scalars(select(Role).where(Role.name == name)).one_or_none()


def lock_role(session: Session, role_id: UUID) -> Role:
    """Row-lock a role so changes guarded by it are serialized.

    ``FOR NO KEY UPDATE`` still lets other transactions insert assignments that
    reference the role, since their foreign-key checks take only a key-share lock.
    """
    statement = select(Role).where(Role.id == role_id).with_for_update(key_share=True)
    return session.scalars(statement).one()


def get_user_with_roles(session: Session, user_id: UUID) -> User | None:
    statement = (
        select(User)
        .options(_WITH_ROLES)
        .where(User.id == user_id)
        .execution_options(populate_existing=True)
    )
    return session.scalars(statement).one_or_none()


def list_users(
    session: Session, *, offset: int, limit: int, email_search: str | None
) -> tuple[list[User], int]:
    """Return one page of users ordered by email, plus the total matching count.

    ``email_search`` must already be normalized; it is matched as a literal,
    case-insensitive substring.
    """
    condition = (
        func.lower(User.email).contains(email_search, autoescape=True) if email_search else None
    )
    count_statement = select(func.count()).select_from(User)
    page_statement = (
        select(User)
        .options(_WITH_ROLES)
        .order_by(User.email, User.id)
        .execution_options(populate_existing=True)
    )
    if condition is not None:
        count_statement = count_statement.where(condition)
        page_statement = page_statement.where(condition)

    total = session.scalars(count_statement).one()
    users = list(session.scalars(page_statement.offset(offset).limit(limit)))
    return users, total


def get_role_names(session: Session, user_id: UUID) -> list[str]:
    statement = (
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.name)
    )
    return list(session.scalars(statement))


def get_permission_keys(session: Session, user_id: UUID) -> list[str]:
    """Return the distinct union of permissions granted by all of a user's roles."""
    statement = (
        select(Permission.key)
        .join(role_permissions, role_permissions.c.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == role_permissions.c.role_id)
        .where(UserRole.user_id == user_id)
        .distinct()
        .order_by(Permission.key)
    )
    return list(session.scalars(statement))


def add_user_role(
    session: Session, *, user_id: UUID, role_id: UUID, assigned_by_user_id: UUID | None
) -> bool:
    """Assign a role unless already assigned. Returns whether a row was inserted.

    An existing assignment, including its audit actor, is left unchanged.
    """
    statement = (
        insert(UserRole)
        .values(user_id=user_id, role_id=role_id, assigned_by_user_id=assigned_by_user_id)
        .on_conflict_do_nothing(index_elements=[UserRole.user_id, UserRole.role_id])
        .returning(UserRole.user_id)
    )
    return session.execute(statement).first() is not None


def remove_user_role(session: Session, *, user_id: UUID, role_id: UUID) -> bool:
    """Remove an assignment if present. Returns whether a row was deleted."""
    statement = (
        delete(UserRole)
        .where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        .returning(UserRole.user_id)
    )
    return session.execute(statement).first() is not None


def has_user_role(session: Session, *, user_id: UUID, role_id: UUID) -> bool:
    statement = select(UserRole.user_id).where(
        UserRole.user_id == user_id, UserRole.role_id == role_id
    )
    return session.scalars(statement).first() is not None


def count_active_verified_users_with_role(session: Session, role_id: UUID) -> int:
    statement = (
        select(func.count())
        .select_from(UserRole)
        .join(User, User.id == UserRole.user_id)
        .where(UserRole.role_id == role_id, User.is_active, User.is_verified)
    )
    return session.scalars(statement).one()
