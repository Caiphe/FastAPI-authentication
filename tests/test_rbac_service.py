"""RBAC business rules and transaction boundaries."""

import dataclasses
import threading
import time
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core import database
from app.rbac import repository
from app.rbac.catalog import PermissionKey, RoleName
from app.rbac.exceptions import (
    DefaultRoleMissingError,
    IneligibleAdministratorError,
    LastAdministratorError,
    PermissionDeniedError,
    RoleNotFoundError,
    UserNotFoundError,
)
from app.rbac.models import UserRole
from app.rbac.service import (
    Authorization,
    PermissionInfo,
    RbacService,
    RoleInfo,
    UserAccount,
)
from app.users.models import User
from tests.conftest import assignment, make_user

pytestmark = pytest.mark.integration

ALL_PERMISSIONS = ("profile:read", "roles:assign", "roles:read", "users:read")


@pytest.fixture
def service(db_session: Session) -> RbacService:
    return RbacService(db_session)


@pytest.fixture
def no_admins(db_session: Session) -> None:
    """Start from a known administrator population inside the rolled-back transaction."""
    admin = repository.get_role_by_name(db_session, RoleName.ADMIN)
    assert admin is not None
    db_session.execute(delete(UserRole).where(UserRole.role_id == admin.id))


# Reads


def test_catalog_reads(service: RbacService) -> None:
    permissions = service.list_permissions()
    assert [p.key for p in permissions] == list(ALL_PERMISSIONS)
    assert permissions[0] == PermissionInfo(
        key="profile:read", description="Read the authenticated user's own profile."
    )
    assert service.list_roles() == [
        RoleInfo(
            name="admin", description="Full administrative access.", permissions=ALL_PERMISSIONS
        ),
        RoleInfo(
            name="user", description="Standard account access.", permissions=("profile:read",)
        ),
    ]


def test_get_user_returns_public_account_state(db_session: Session, service: RbacService) -> None:
    user = make_user(db_session, roles=(RoleName.USER, RoleName.ADMIN), is_verified=False)

    account = service.get_user(user.id)
    assert account == UserAccount(
        id=user.id,
        email=user.email,
        is_active=True,
        is_verified=False,
        created_at=user.created_at,
        roles=("admin", "user"),
    )
    assert "assigned_by_user_id" not in {f.name for f in dataclasses.fields(UserAccount)}

    with pytest.raises(UserNotFoundError):
        service.get_user(uuid4())


def test_list_users_normalizes_search_and_reports_page(
    db_session: Session, service: RbacService
) -> None:
    tag = uuid4().hex
    first = make_user(db_session, f"a-{tag}@example.com", roles=(RoleName.USER,))
    second = make_user(db_session, f"b-{tag}@example.com")

    page = service.list_users(offset=0, limit=1, email=f"  A-{tag.upper()}  ")
    assert (page.total, page.offset, page.limit) == (1, 0, 1)
    assert [u.id for u in page.items] == [first.id]
    assert page.items[0].roles == ("user",)

    page = service.list_users(offset=1, limit=1, email=tag)
    assert page.total == 2
    assert [u.id for u in page.items] == [second.id]
    assert page.items[0].roles == ()

    # A blank search is no filter at all.
    assert service.list_users(offset=0, limit=1, email="   ").total >= 2


def test_find_user_id_normalizes_email(db_session: Session, service: RbacService) -> None:
    user = make_user(db_session)
    assert service.find_user_id(f"  {user.email.upper()}  ") == user.id
    with pytest.raises(UserNotFoundError):
        service.find_user_id(f"missing-{uuid4().hex}@example.com")


def test_authorization_is_union_of_roles(db_session: Session, service: RbacService) -> None:
    both = make_user(db_session, roles=(RoleName.ADMIN, RoleName.USER))
    authorization = service.get_authorization(both.id)
    assert authorization == Authorization(roles=("admin", "user"), permissions=ALL_PERMISSIONS)
    assert authorization.allows(PermissionKey.ROLES_ASSIGN)

    plain = service.get_authorization(make_user(db_session, roles=(RoleName.USER,)).id)
    assert plain.permissions == ("profile:read",)
    assert not plain.allows(PermissionKey.USERS_READ)
    with pytest.raises(PermissionDeniedError):
        plain.require(PermissionKey.USERS_READ)
    plain.require(PermissionKey.PROFILE_READ)


def test_authorization_reflects_database_changes_immediately(
    db_session: Session, service: RbacService
) -> None:
    make_user(db_session, roles=(RoleName.ADMIN,))
    user = make_user(db_session, roles=(RoleName.USER,))
    assert not service.get_authorization(user.id).allows(PermissionKey.ROLES_READ)
    service.grant_role(user.id, RoleName.ADMIN)
    assert service.get_authorization(user.id).allows(PermissionKey.ROLES_READ)
    service.revoke_role(user.id, RoleName.ADMIN)
    assert not service.get_authorization(user.id).allows(PermissionKey.ROLES_READ)


# Grants


def test_grant_records_actor_and_is_idempotent(db_session: Session, service: RbacService) -> None:
    actor = make_user(db_session)
    target = make_user(db_session)

    assert service.grant_role(target.id, RoleName.ADMIN, assigned_by_user_id=actor.id) is True
    granted = assignment(db_session, target.id, "admin")
    assert granted is not None and granted.assigned_by_user_id == actor.id

    assert service.grant_role(target.id, RoleName.ADMIN) is False
    repeated = assignment(db_session, target.id, "admin")
    assert repeated is not None
    assert (repeated.assigned_by_user_id, repeated.assigned_at) == (actor.id, granted.assigned_at)


def test_system_grant_has_no_actor(db_session: Session, service: RbacService) -> None:
    target = make_user(db_session)
    service.grant_role(target.id, RoleName.USER)
    granted = assignment(db_session, target.id, "user")
    assert granted is not None and granted.assigned_by_user_id is None


def test_grant_rejects_unknown_user_and_role(db_session: Session, service: RbacService) -> None:
    with pytest.raises(UserNotFoundError):
        service.grant_role(uuid4(), RoleName.USER)
    with pytest.raises(RoleNotFoundError):
        service.grant_role(make_user(db_session).id, "superuser")


@pytest.mark.parametrize(("is_active", "is_verified"), [(False, True), (True, False)])
def test_admin_grant_requires_active_verified_target(
    db_session: Session, service: RbacService, is_active: bool, is_verified: bool
) -> None:
    target = make_user(db_session, is_active=is_active, is_verified=is_verified)
    with pytest.raises(IneligibleAdministratorError):
        service.grant_role(target.id, RoleName.ADMIN)
    assert assignment(db_session, target.id, "admin") is None


def test_non_admin_roles_may_be_granted_to_unverified_accounts(
    db_session: Session, service: RbacService
) -> None:
    target = make_user(db_session, is_verified=False)
    assert service.grant_role(target.id, RoleName.USER) is True


def test_default_role_is_staged_without_committing(
    db_session: Session, service: RbacService
) -> None:
    user = make_user(db_session, is_verified=False)
    service.assign_default_role(user.id)
    assert repository.get_role_names(db_session, user.id) == ["user"]

    # The caller owns the transaction: rolling back discards the assignment.
    db_session.rollback()
    assert repository.get_role_names(db_session, user.id) == []


def test_default_role_missing_raises(
    db_session: Session, service: RbacService, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(repository, "get_role_by_name", lambda session, name: None)
    with pytest.raises(DefaultRoleMissingError):
        service.assign_default_role(uuid4())


def test_failed_grant_rolls_back(
    db_session: Session, service: RbacService, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_user(db_session)
    db_session.commit()
    real_add = repository.add_user_role

    def add_then_fail(session: Session, **kwargs: UUID | None) -> bool:
        real_add(session, **kwargs)  # type: ignore[arg-type]
        raise RuntimeError("database failure")

    monkeypatch.setattr(repository, "add_user_role", add_then_fail)
    with pytest.raises(RuntimeError):
        service.grant_role(target.id, RoleName.USER)
    assert repository.get_role_names(db_session, target.id) == []


# Revocation and last-administrator protection


def test_revoke_is_idempotent(db_session: Session, service: RbacService) -> None:
    user = make_user(db_session, roles=(RoleName.USER,))
    assert service.revoke_role(user.id, RoleName.USER) is True
    assert service.revoke_role(user.id, RoleName.USER) is False
    assert repository.get_role_names(db_session, user.id) == []


def test_revoke_rejects_unknown_user_and_role(db_session: Session, service: RbacService) -> None:
    with pytest.raises(UserNotFoundError):
        service.revoke_role(uuid4(), RoleName.USER)
    with pytest.raises(RoleNotFoundError):
        service.revoke_role(make_user(db_session).id, "superuser")


@pytest.mark.usefixtures("no_admins")
def test_last_admin_cannot_be_removed(db_session: Session, service: RbacService) -> None:
    only = make_user(db_session, roles=(RoleName.ADMIN,))
    db_session.commit()

    with pytest.raises(LastAdministratorError):
        service.revoke_role(only.id, RoleName.ADMIN)
    assert repository.get_role_names(db_session, only.id) == ["admin"]
    # The session is still usable after the refused removal.
    assert service.get_user(only.id).roles == ("admin",)


@pytest.mark.usefixtures("no_admins")
def test_admin_removal_allowed_while_another_eligible_admin_remains(
    db_session: Session, service: RbacService
) -> None:
    first = make_user(db_session, roles=(RoleName.ADMIN,))
    second = make_user(db_session, roles=(RoleName.ADMIN,))

    assert service.revoke_role(first.id, RoleName.ADMIN) is True
    with pytest.raises(LastAdministratorError):
        service.revoke_role(second.id, RoleName.ADMIN)


@pytest.mark.usefixtures("no_admins")
def test_ineligible_admins_do_not_count_and_can_always_be_removed(
    db_session: Session, service: RbacService
) -> None:
    eligible = make_user(db_session, roles=(RoleName.ADMIN,))
    disabled = make_user(db_session, roles=(RoleName.ADMIN,), is_active=False)
    unverified = make_user(db_session, roles=(RoleName.ADMIN,), is_verified=False)
    # Commit setup: the refused removal below rolls back the service's transaction.
    db_session.commit()

    with pytest.raises(LastAdministratorError):
        service.revoke_role(eligible.id, RoleName.ADMIN)
    assert service.revoke_role(disabled.id, RoleName.ADMIN) is True
    assert service.revoke_role(unverified.id, RoleName.ADMIN) is True


@pytest.mark.usefixtures("no_admins")
def test_absent_admin_assignment_revokes_without_last_admin_check(
    db_session: Session, service: RbacService
) -> None:
    make_user(db_session, roles=(RoleName.ADMIN,))
    plain = make_user(db_session, roles=(RoleName.USER,))
    assert service.revoke_role(plain.id, RoleName.ADMIN) is False


# Concurrency


def test_concurrent_last_admin_removals_leave_an_administrator(
    committed_admins: list[User], monkeypatch: pytest.MonkeyPatch
) -> None:
    with database.SessionFactory() as session:
        admin = repository.get_role_by_name(session, RoleName.ADMIN)
        assert admin is not None
        others = repository.count_active_verified_users_with_role(session, admin.id) - 2

    # Widen the race: pause between counting administrators and removing the role.
    real_count = repository.count_active_verified_users_with_role

    def slow_count(session: Session, role_id: UUID) -> int:
        count = real_count(session, role_id)
        time.sleep(0.3)
        return count

    monkeypatch.setattr(repository, "count_active_verified_users_with_role", slow_count)
    barrier = threading.Barrier(2)
    outcomes: list[bool | Exception] = []
    lock = threading.Lock()

    def remove(user: User) -> None:
        with database.SessionFactory() as session:
            barrier.wait()
            try:
                result: bool | Exception = RbacService(session).revoke_role(user.id, RoleName.ADMIN)
            except Exception as error:
                result = error
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=remove, args=(user,)) for user in committed_admins]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(outcomes) == 2
    with database.SessionFactory() as session:
        remaining = repository.count_active_verified_users_with_role(session, admin.id)
    assert remaining >= 1
    if others == 0:
        assert sorted(type(o).__name__ for o in outcomes) == ["LastAdministratorError", "bool"]
        assert remaining == 1
