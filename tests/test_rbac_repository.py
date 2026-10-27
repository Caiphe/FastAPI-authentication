"""RBAC persistence queries against the migrated PostgreSQL schema."""

from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.rbac import repository
from app.rbac.catalog import PermissionKey, RoleName
from app.rbac.models import Role, UserRole
from app.users.models import User
from tests.conftest import make_user

pytestmark = pytest.mark.integration


def seeded_role(session: Session, name: RoleName) -> Role:
    role = repository.get_role_by_name(session, name)
    assert role is not None
    return role


def test_catalog_listing_is_seeded_and_ordered(db_session: Session) -> None:
    assert [p.key for p in repository.list_permissions(db_session)] == [
        "profile:read",
        "roles:assign",
        "roles:read",
        "users:read",
    ]
    roles = repository.list_roles(db_session)
    assert [role.name for role in roles] == ["admin", "user"]
    assert [p.key for p in roles[0].permissions] == [
        "profile:read",
        "roles:assign",
        "roles:read",
        "users:read",
    ]
    assert [p.key for p in roles[1].permissions] == ["profile:read"]


def test_get_role_by_name(db_session: Session) -> None:
    assert seeded_role(db_session, RoleName.ADMIN).name == "admin"
    assert repository.get_role_by_name(db_session, "missing") is None


def test_get_user_with_roles(db_session: Session) -> None:
    user = make_user(db_session, roles=(RoleName.USER, RoleName.ADMIN))
    db_session.expunge_all()

    loaded = repository.get_user_with_roles(db_session, user.id)
    assert loaded is not None
    assert sorted(a.role.name for a in loaded.role_assignments) == ["admin", "user"]
    assert repository.get_user_with_roles(db_session, uuid4()) is None


def test_role_names_and_permission_union(db_session: Session) -> None:
    user = make_user(db_session, roles=(RoleName.USER, RoleName.ADMIN))
    assert repository.get_role_names(db_session, user.id) == ["admin", "user"]
    # profile:read is granted by both roles but appears once.
    assert repository.get_permission_keys(db_session, user.id) == sorted(PermissionKey)

    plain = make_user(db_session, roles=(RoleName.USER,))
    assert repository.get_permission_keys(db_session, plain.id) == ["profile:read"]

    nobody = make_user(db_session)
    assert repository.get_role_names(db_session, nobody.id) == []
    assert repository.get_permission_keys(db_session, nobody.id) == []


def test_list_users_paginates_searches_and_orders(db_session: Session) -> None:
    tag = uuid4().hex
    emails = [f"{prefix}-{tag}@example.com" for prefix in ("carol", "alice", "bob")]
    for email in emails:
        make_user(db_session, email, roles=(RoleName.USER,))
    make_user(db_session, f"x_y%z-{tag}@example.com")

    users, total = repository.list_users(db_session, offset=0, limit=2, email_search=tag)
    assert total == 4
    assert [u.email for u in users] == sorted(emails)[:2]

    users, total = repository.list_users(db_session, offset=2, limit=2, email_search=tag)
    assert total == 4
    assert [u.email for u in users] == [sorted(emails)[2], f"x_y%z-{tag}@example.com"]
    assert [a.role.name for a in users[0].role_assignments] == ["user"]

    # LIKE wildcards in the search term are matched literally.
    users, total = repository.list_users(db_session, offset=0, limit=10, email_search="_y%z-" + tag)
    assert total == 1 and users[0].email.startswith("x_y%z")
    users, total = repository.list_users(db_session, offset=0, limit=10, email_search="%" + tag)
    assert (users, total) == ([], 0)

    users, total = repository.list_users(db_session, offset=10, limit=10, email_search=tag)
    assert (users, total) == ([], 4)


def test_list_users_without_search_counts_everyone(db_session: Session) -> None:
    make_user(db_session)
    everyone = len(db_session.scalars(select(User.id)).all())
    users, total = repository.list_users(db_session, offset=0, limit=100, email_search=None)
    assert total == everyone
    assert [u.email for u in users] == sorted(u.email for u in users)


def test_add_and_remove_user_role_are_idempotent(db_session: Session) -> None:
    actor = make_user(db_session)
    user = make_user(db_session)
    admin = seeded_role(db_session, RoleName.ADMIN)

    assert repository.add_user_role(
        db_session, user_id=user.id, role_id=admin.id, assigned_by_user_id=actor.id
    )
    assert not repository.add_user_role(
        db_session, user_id=user.id, role_id=admin.id, assigned_by_user_id=None
    )
    assignment = db_session.scalars(select(UserRole).where(UserRole.user_id == user.id)).one()
    # The original audit actor is kept; the repeat grant was a no-op.
    assert assignment.assigned_by_user_id == actor.id

    assert repository.remove_user_role(db_session, user_id=user.id, role_id=admin.id)
    assert not repository.remove_user_role(db_session, user_id=user.id, role_id=admin.id)
    assert repository.get_role_names(db_session, user.id) == []


def test_count_active_verified_users_with_role(db_session: Session) -> None:
    admin = seeded_role(db_session, RoleName.ADMIN)
    db_session.execute(delete(UserRole).where(UserRole.role_id == admin.id))

    make_user(db_session, roles=(RoleName.ADMIN,))
    make_user(db_session, roles=(RoleName.ADMIN,))
    make_user(db_session, roles=(RoleName.ADMIN,), is_active=False)
    make_user(db_session, roles=(RoleName.ADMIN,), is_verified=False)
    make_user(db_session, roles=(RoleName.USER,))

    assert repository.count_active_verified_users_with_role(db_session, admin.id) == 2


def test_lock_role_returns_the_role(db_session: Session) -> None:
    admin = seeded_role(db_session, RoleName.ADMIN)
    assert repository.lock_role(db_session, admin.id) is admin
