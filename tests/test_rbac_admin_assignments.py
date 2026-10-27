"""Role assignment API: grant, revoke, audit, idempotency, and last-admin safety."""

import threading
import time
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core import database
from app.core.config import Settings
from app.rbac import repository
from app.rbac.catalog import PermissionKey, RoleName
from app.rbac.models import Role, UserRole
from app.users.models import User
from tests.conftest import bearer, holder_of, make_user

pytestmark = pytest.mark.integration

ME = "/api/v1/users/me"


def role_url(user_id: UUID | str, role: str) -> str:
    return f"/api/v1/admin/users/{user_id}/roles/{role}"


def assignments(session: Session, user_id: UUID) -> dict[str, UserRole]:
    rows = session.scalars(
        select(UserRole)
        .join(Role)
        .where(UserRole.user_id == user_id)
        .execution_options(populate_existing=True)
    )
    return {row.role.name: row for row in rows}


def assert_no_content(response: Any) -> None:
    assert response.status_code == 204, response.text
    assert response.content == b""


# Tests that expect a failed mutation commit their setup first: the service rolls
# back on failure, which would otherwise also discard uncommitted fixture data in
# the shared test session.


def assert_error(response: Any, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body["error"]) == {"code", "message", "details"}
    assert body["error"]["code"] == code


@pytest.fixture
def actor(db_session: Session) -> User:
    return make_user(db_session, roles=(RoleName.ADMIN,))


@pytest.fixture
def headers(settings: Settings, actor: User) -> dict[str, str]:
    return bearer(settings, actor)


@pytest.fixture
def only_actor_is_admin(db_session: Session, actor: User) -> None:
    """Leave ``actor`` as the sole administrator inside the rolled-back transaction."""
    admin = repository.get_role_by_name(db_session, RoleName.ADMIN)
    assert admin is not None
    db_session.execute(
        delete(UserRole).where(UserRole.role_id == admin.id, UserRole.user_id != actor.id)
    )
    db_session.commit()


# Grants


def test_grant_returns_204_and_records_the_actor(
    client: TestClient, db_session: Session, actor: User, headers: dict[str, str]
) -> None:
    target = make_user(db_session)

    assert_no_content(client.put(role_url(target.id, "admin"), headers=headers))

    granted = assignments(db_session, target.id)["admin"]
    assert granted.assigned_by_user_id == actor.id


def test_repeated_grant_is_a_no_op(
    client: TestClient, db_session: Session, actor: User, headers: dict[str, str]
) -> None:
    target = make_user(db_session)
    client.put(role_url(target.id, "user"), headers=headers)
    first = assignments(db_session, target.id)["user"]

    assert_no_content(client.put(role_url(target.id, "user"), headers=headers))

    after = assignments(db_session, target.id)
    assert list(after) == ["user"]
    assert (after["user"].assigned_at, after["user"].assigned_by_user_id) == (
        first.assigned_at,
        actor.id,
    )


def test_user_role_may_be_granted_to_unverified_accounts(
    client: TestClient, db_session: Session, headers: dict[str, str]
) -> None:
    target = make_user(db_session, is_verified=False)
    assert_no_content(client.put(role_url(target.id, "user"), headers=headers))


@pytest.mark.parametrize(("is_active", "is_verified"), [(False, True), (True, False)])
def test_admin_grant_to_ineligible_account_conflicts(
    client: TestClient,
    db_session: Session,
    headers: dict[str, str],
    is_active: bool,
    is_verified: bool,
) -> None:
    target = make_user(db_session, is_active=is_active, is_verified=is_verified)
    db_session.commit()

    response = client.put(role_url(target.id, "admin"), headers=headers)

    assert_error(response, 409, "admin_target_ineligible")
    assert assignments(db_session, target.id) == {}


# Revocations


def test_revoke_returns_204_and_is_idempotent(
    client: TestClient, db_session: Session, headers: dict[str, str]
) -> None:
    target = make_user(db_session, roles=(RoleName.USER,))

    assert_no_content(client.delete(role_url(target.id, "user"), headers=headers))
    assert_no_content(client.delete(role_url(target.id, "user"), headers=headers))
    assert assignments(db_session, target.id) == {}


@pytest.mark.usefixtures("only_actor_is_admin")
def test_removing_the_last_admin_conflicts(
    client: TestClient, db_session: Session, actor: User, headers: dict[str, str]
) -> None:
    response = client.delete(role_url(actor.id, "admin"), headers=headers)

    assert_error(response, 409, "last_administrator")
    assert "admin" in assignments(db_session, actor.id)
    assert client.get(ME, headers=headers).json()["roles"] == ["admin"]


@pytest.mark.usefixtures("only_actor_is_admin")
def test_self_removal_succeeds_while_another_admin_remains(
    client: TestClient, db_session: Session, actor: User, headers: dict[str, str]
) -> None:
    other = make_user(db_session, roles=(RoleName.ADMIN,))
    permissions_url = "/api/v1/admin/permissions"
    assert client.get(permissions_url, headers=headers).status_code == 200

    assert_no_content(client.delete(role_url(actor.id, "admin"), headers=headers))

    # The same, still-valid token loses access on its very next request.
    assert_error(client.get(permissions_url, headers=headers), 403, "permission_denied")
    assert_error(
        client.delete(role_url(other.id, "admin"), headers=headers), 403, "permission_denied"
    )
    assert "admin" in assignments(db_session, other.id)


def test_grant_applies_to_the_targets_existing_token(
    client: TestClient,
    db_session: Session,
    settings: Settings,
    headers: dict[str, str],
) -> None:
    target = make_user(db_session, roles=(RoleName.USER,))
    target_headers = bearer(settings, target)
    catalog = "/api/v1/admin/roles"
    assert client.get(catalog, headers=target_headers).status_code == 403

    client.put(role_url(target.id, "admin"), headers=headers)
    assert client.get(catalog, headers=target_headers).status_code == 200

    client.delete(role_url(target.id, "admin"), headers=headers)
    assert client.get(catalog, headers=target_headers).status_code == 403


# Lookup and validation failures


@pytest.mark.parametrize("method", ["put", "delete"])
def test_unknown_user_and_role_return_404(
    client: TestClient, db_session: Session, headers: dict[str, str], method: str
) -> None:
    target = make_user(db_session, roles=(RoleName.USER,))
    db_session.commit()
    send = getattr(client, method)

    assert_error(send(role_url(uuid4(), "user"), headers=headers), 404, "user_not_found")
    assert_error(send(role_url(target.id, "superuser"), headers=headers), 404, "role_not_found")
    assert list(assignments(db_session, target.id)) == ["user"]


@pytest.mark.parametrize("method", ["put", "delete"])
def test_malformed_identifiers_are_validation_errors(
    client: TestClient, headers: dict[str, str], method: str
) -> None:
    send = getattr(client, method)

    assert_error(send(role_url("not-a-uuid", "user"), headers=headers), 422, "validation_error")
    assert_error(send(role_url(uuid4(), "r" * 65), headers=headers), 422, "validation_error")


# Authentication and authorization


@pytest.mark.parametrize("method", ["put", "delete"])
def test_assignment_requires_authentication(client: TestClient, method: str) -> None:
    response = getattr(client, method)(role_url(uuid4(), "user"))
    assert_error(response, 401, "not_authenticated")


@pytest.mark.parametrize("method", ["put", "delete"])
def test_assignment_requires_roles_assign(
    client: TestClient, db_session: Session, settings: Settings, method: str
) -> None:
    target = make_user(db_session, roles=(RoleName.USER,))
    # Reading users and roles is not enough to change them.
    for permission in (PermissionKey.USERS_READ, PermissionKey.ROLES_READ):
        headers = holder_of(db_session, settings, permission)
        response = getattr(client, method)(role_url(target.id, "user"), headers=headers)
        assert_error(response, 403, "permission_denied")
    assert list(assignments(db_session, target.id)) == ["user"]


def test_roles_assign_alone_is_sufficient(
    client: TestClient, db_session: Session, settings: Settings
) -> None:
    headers = holder_of(db_session, settings, PermissionKey.ROLES_ASSIGN)
    target = make_user(db_session)

    assert_no_content(client.put(role_url(target.id, "user"), headers=headers))
    assert_no_content(client.delete(role_url(target.id, "user"), headers=headers))


# Concurrency


def test_concurrent_last_admin_removals_over_http_leave_an_administrator(
    make_app: Callable[..., FastAPI],
    settings: Settings,
    committed_admins: list[User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = committed_admins
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
    statuses: list[int] = []
    lock = threading.Lock()

    # Each administrator removes the other, each on its own per-request sessions.
    def remove(actor: User, target: User) -> None:
        with TestClient(make_app()) as client:
            barrier.wait()
            response = client.delete(role_url(target.id, "admin"), headers=bearer(settings, actor))
        with lock:
            statuses.append(response.status_code)

    threads = [
        threading.Thread(target=remove, args=(first, second)),
        threading.Thread(target=remove, args=(second, first)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(statuses) == 2
    with database.SessionFactory() as session:
        remaining = real_count(session, admin.id)
    assert remaining >= 1
    if others == 0:
        assert sorted(statuses) == [204, 409]
        assert remaining == 1
