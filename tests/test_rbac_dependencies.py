"""Permission dependencies and the authorization details on /users/me."""

from collections.abc import Callable
from typing import Annotated, Any
from uuid import UUID

import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import hash_password
from app.rbac import repository
from app.rbac.catalog import PermissionKey, RoleName
from app.rbac.dependencies import AuthorizationContext, require_permission
from app.rbac.service import RbacService
from tests.conftest import bearer, make_user

pytestmark = pytest.mark.integration

ME = "/api/v1/users/me"
PASSWORD = "correct horse battery staple"
PERMISSION_DENIED = {
    "error": {
        "code": "permission_denied",
        "message": "You do not have permission to perform this action.",
        "details": None,
    }
}
ALL_PERMISSIONS = ["profile:read", "roles:assign", "roles:read", "users:read"]


def test_me_requires_authentication(client: TestClient) -> None:
    response = client.get(ME)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"


def test_me_requires_profile_read(
    client: TestClient, db_session: Session, settings: Settings
) -> None:
    user = make_user(db_session)

    response = client.get(ME, headers=bearer(settings, user))

    assert response.status_code == 403
    assert response.json() == PERMISSION_DENIED


def test_me_returns_sorted_roles_and_effective_permissions(
    client: TestClient, db_session: Session, settings: Settings
) -> None:
    user = make_user(db_session, roles=(RoleName.USER, RoleName.ADMIN))

    response = client.get(ME, headers=bearer(settings, user))

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "is_verified": True,
        "created_at": user.created_at.isoformat().replace("+00:00", "Z"),
        "roles": ["admin", "user"],
        "effective_permissions": ALL_PERMISSIONS,
    }


def test_role_changes_apply_to_an_already_issued_token(
    client: TestClient, db_session: Session, settings: Settings
) -> None:
    make_user(db_session, roles=(RoleName.ADMIN,))  # keeps the admin role removable
    user = make_user(db_session)
    headers = bearer(settings, user)
    service = RbacService(db_session)

    assert client.get(ME, headers=headers).status_code == 403

    service.grant_role(user.id, RoleName.USER)
    response = client.get(ME, headers=headers)
    assert response.status_code == 200
    assert response.json()["effective_permissions"] == ["profile:read"]

    service.grant_role(user.id, RoleName.ADMIN)
    response = client.get(ME, headers=headers)
    assert response.json()["roles"] == ["admin", "user"]
    assert response.json()["effective_permissions"] == ALL_PERMISSIONS

    service.revoke_role(user.id, RoleName.ADMIN)
    assert client.get(ME, headers=headers).json()["effective_permissions"] == ["profile:read"]

    service.revoke_role(user.id, RoleName.USER)
    assert client.get(ME, headers=headers).json() == PERMISSION_DENIED


# The dependency factory on an arbitrary route


ReadRoles = Annotated[AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_READ))]
ReadProfile = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.PROFILE_READ))
]


@pytest.fixture
def probe_client(make_app: Callable[..., FastAPI], db_session: Session) -> TestClient:
    application = make_app(db_session)

    @application.get("/probe")
    def probe(roles: ReadRoles, profile: ReadProfile) -> dict[str, Any]:
        assert roles is profile
        return {
            "user_id": str(roles.user.id),
            "roles": list(roles.authorization.roles),
            "permissions": list(roles.authorization.permissions),
        }

    return TestClient(application)


def test_require_permission_passes_context_and_loads_once_per_request(
    probe_client: TestClient,
    db_session: Session,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[UUID] = []
    real = repository.get_permission_keys

    def counting(session: Session, user_id: UUID) -> list[str]:
        calls.append(user_id)
        return real(session, user_id)

    monkeypatch.setattr(repository, "get_permission_keys", counting)
    admin = make_user(db_session, roles=(RoleName.ADMIN,))

    response = probe_client.get("/probe", headers=bearer(settings, admin))

    assert response.status_code == 200
    assert response.json() == {
        "user_id": str(admin.id),
        "roles": ["admin"],
        "permissions": ALL_PERMISSIONS,
    }
    assert calls == [admin.id]

    # Nothing is cached between requests.
    probe_client.get("/probe", headers=bearer(settings, admin))
    assert calls == [admin.id, admin.id]


def test_require_permission_denies_a_single_missing_permission(
    probe_client: TestClient, db_session: Session, settings: Settings
) -> None:
    user = make_user(db_session, roles=(RoleName.USER,))

    response = probe_client.get("/probe", headers=bearer(settings, user))

    assert response.status_code == 403
    assert response.json() == PERMISSION_DENIED


def test_require_permission_rejects_missing_authentication(probe_client: TestClient) -> None:
    response = probe_client.get("/probe")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"


def test_login_token_stays_identity_only_for_administrators(
    client: TestClient, db_session: Session
) -> None:
    admin = make_user(db_session, roles=(RoleName.ADMIN, RoleName.USER))
    admin.hashed_password = hash_password(PASSWORD)
    db_session.flush()

    login = client.post("/api/v1/auth/login", json={"email": admin.email, "password": PASSWORD})
    assert login.status_code == 200, login.text

    claims = jwt.decode(login.json()["access_token"], options={"verify_signature": False})
    assert set(claims) == {"sub", "iat", "exp", "jti"}
