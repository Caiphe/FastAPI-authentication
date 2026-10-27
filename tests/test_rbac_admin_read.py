"""Read-only administration API: catalog, user list, and user detail."""

from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.rbac.catalog import PermissionKey, RoleName
from app.users.models import User
from tests.conftest import bearer, holder_of, make_user

pytestmark = pytest.mark.integration

PERMISSIONS = "/api/v1/admin/permissions"
ROLES = "/api/v1/admin/roles"
USERS = "/api/v1/admin/users"
ALL_PERMISSIONS = ["profile:read", "roles:assign", "roles:read", "users:read"]
ADMIN_USER_FIELDS = {"id", "email", "is_active", "is_verified", "created_at", "roles"}


def timestamp(user: User) -> str:
    return user.created_at.isoformat().replace("+00:00", "Z")


def error_code(response: Any) -> str:
    code: str = response.json()["error"]["code"]
    return code


@pytest.fixture
def admin_headers(db_session: Session, settings: Settings) -> dict[str, str]:
    return bearer(settings, make_user(db_session, roles=(RoleName.ADMIN,)))


# Catalog


def test_list_permissions(client: TestClient, admin_headers: dict[str, str]) -> None:
    response = client.get(PERMISSIONS, headers=admin_headers)

    assert response.status_code == 200
    assert response.json() == [
        {"key": "profile:read", "description": "Read the authenticated user's own profile."},
        {"key": "roles:assign", "description": "Assign and remove roles from users."},
        {"key": "roles:read", "description": "List the role and permission catalog."},
        {
            "key": "users:read",
            "description": "List and inspect users through the administration API.",
        },
    ]


def test_list_roles(client: TestClient, admin_headers: dict[str, str]) -> None:
    response = client.get(ROLES, headers=admin_headers)

    assert response.status_code == 200
    assert response.json() == [
        {
            "name": "admin",
            "description": "Full administrative access.",
            "permissions": ALL_PERMISSIONS,
        },
        {
            "name": "user",
            "description": "Standard account access.",
            "permissions": ["profile:read"],
        },
    ]


# User list


def test_list_users_searches_sorts_and_paginates(
    client: TestClient, db_session: Session, admin_headers: dict[str, str]
) -> None:
    tag = uuid4().hex
    carol = make_user(db_session, f"carol-{tag}@example.com", roles=(RoleName.USER,))
    alice = make_user(db_session, f"alice-{tag}@example.com", roles=(RoleName.USER, RoleName.ADMIN))
    bob = make_user(db_session, f"bob-{tag}@example.com", is_active=False, is_verified=False)

    first = client.get(
        USERS, params={"email": f"  {tag.upper()} ", "limit": 2}, headers=admin_headers
    )
    assert first.status_code == 200
    body = first.json()
    assert {key: body[key] for key in ("total", "offset", "limit")} == {
        "total": 3,
        "offset": 0,
        "limit": 2,
    }
    assert body["items"] == [
        {
            "id": str(alice.id),
            "email": alice.email,
            "is_active": True,
            "is_verified": True,
            "created_at": timestamp(alice),
            "roles": ["admin", "user"],
        },
        {
            "id": str(bob.id),
            "email": bob.email,
            "is_active": False,
            "is_verified": False,
            "created_at": timestamp(bob),
            "roles": [],
        },
    ]

    second = client.get(
        USERS, params={"email": tag, "offset": 2, "limit": 2}, headers=admin_headers
    ).json()
    assert (second["total"], second["offset"], second["limit"]) == (3, 2, 2)
    assert [item["id"] for item in second["items"]] == [str(carol.id)]
    assert set(second["items"][0]) == ADMIN_USER_FIELDS


def test_list_users_defaults_and_empty_results(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    default = client.get(USERS, headers=admin_headers).json()
    assert (default["offset"], default["limit"]) == (0, 50)
    assert default["total"] >= 1
    emails = [item["email"] for item in default["items"]]
    assert emails == sorted(emails)

    empty = client.get(USERS, params={"email": uuid4().hex}, headers=admin_headers).json()
    assert empty == {"items": [], "total": 0, "offset": 0, "limit": 50}


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"limit": "many"},
        {"email": "x" * 321},
    ],
    ids=["limit-zero", "limit-too-large", "negative-offset", "non-integer", "long-email"],
)
def test_list_users_validates_query(
    client: TestClient, admin_headers: dict[str, str], params: dict[str, Any]
) -> None:
    response = client.get(USERS, params=params, headers=admin_headers)

    assert response.status_code == 422
    assert error_code(response) == "validation_error"


def test_list_users_accepts_limit_bounds(client: TestClient, admin_headers: dict[str, str]) -> None:
    for limit in (1, 100):
        response = client.get(USERS, params={"limit": limit}, headers=admin_headers)
        assert response.status_code == 200
        assert len(response.json()["items"]) <= limit


# User detail


def test_get_user(client: TestClient, db_session: Session, admin_headers: dict[str, str]) -> None:
    user = make_user(db_session, roles=(RoleName.USER,), is_verified=False)

    response = client.get(f"{USERS}/{user.id}", headers=admin_headers)

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "is_active": True,
        "is_verified": False,
        "created_at": timestamp(user),
        "roles": ["user"],
    }


def test_get_unknown_user_returns_404(client: TestClient, admin_headers: dict[str, str]) -> None:
    response = client.get(f"{USERS}/{uuid4()}", headers=admin_headers)

    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "user_not_found", "message": "The user does not exist.", "details": None}
    }


def test_get_user_rejects_malformed_id(client: TestClient, admin_headers: dict[str, str]) -> None:
    response = client.get(f"{USERS}/not-a-uuid", headers=admin_headers)

    assert response.status_code == 422
    assert error_code(response) == "validation_error"


# Authentication and authorization

ALL_ENDPOINTS = [PERMISSIONS, ROLES, USERS, f"{USERS}/{uuid4()}"]


@pytest.mark.parametrize("path", ALL_ENDPOINTS)
def test_endpoints_require_authentication(client: TestClient, path: str) -> None:
    response = client.get(path)

    assert response.status_code == 401
    assert error_code(response) == "not_authenticated"


@pytest.mark.parametrize("path", ALL_ENDPOINTS)
def test_ordinary_users_are_denied(
    client: TestClient, db_session: Session, settings: Settings, path: str
) -> None:
    headers = bearer(settings, make_user(db_session, roles=(RoleName.USER,)))

    response = client.get(path, headers=headers)

    assert response.status_code == 403
    assert error_code(response) == "permission_denied"


def test_users_read_alone_grants_user_endpoints_only(
    client: TestClient, db_session: Session, settings: Settings
) -> None:
    headers = holder_of(db_session, settings, PermissionKey.USERS_READ)
    target = make_user(db_session)

    assert client.get(USERS, headers=headers).status_code == 200
    assert client.get(f"{USERS}/{target.id}", headers=headers).status_code == 200
    assert client.get(ROLES, headers=headers).status_code == 403
    assert client.get(PERMISSIONS, headers=headers).status_code == 403


def test_roles_read_alone_grants_catalog_endpoints_only(
    client: TestClient, db_session: Session, settings: Settings
) -> None:
    headers = holder_of(db_session, settings, PermissionKey.ROLES_READ)

    assert client.get(ROLES, headers=headers).status_code == 200
    assert client.get(PERMISSIONS, headers=headers).status_code == 200
    assert client.get(USERS, headers=headers).status_code == 403
