"""Login, refresh-cookie issuance, bearer authentication, and /users/me."""

import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from typing import Any
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dispatch import get_email_dispatcher
from app.auth.models import RefreshToken
from app.core import database
from app.core.config import Settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_opaque_token,
    verify_password,
)
from app.core.security import hash_password as real_hash_password
from app.main import create_app
from app.rbac.service import RbacService
from app.users.models import User
from tests.conftest import FakeDispatcher

pytestmark = pytest.mark.integration

LOGIN = "/api/v1/auth/login"
ME = "/api/v1/users/me"
EMAIL = "jane@example.com"
PASSWORD = "correct horse battery staple"
INVALID_CREDENTIALS = {
    "error": {
        "code": "invalid_credentials",
        "message": "Email or password is incorrect.",
        "details": None,
    }
}


@pytest.fixture(scope="module")
def password_hash() -> str:
    return real_hash_password(PASSWORD)


def create_user(
    session: Session,
    password_hash: str,
    *,
    email: str = EMAIL,
    is_verified: bool = True,
    is_active: bool = True,
) -> User:
    user = User(
        email=email,
        hashed_password=password_hash,
        is_verified=is_verified,
        is_active=is_active,
    )
    session.add(user)
    session.flush()
    # Registration grants this role; /users/me requires its permission.
    RbacService(session).assign_default_role(user.id)
    return user


# TestClient returns an httpx or httpx2 response depending on what is installed.
def login(client: TestClient, email: str = EMAIL, password: str = PASSWORD) -> Any:
    return client.post(LOGIN, json={"email": email, "password": password})


def refresh_cookie(response: Any) -> SimpleCookie:
    cookie: SimpleCookie = SimpleCookie()
    cookie.load(response.headers["set-cookie"])
    return cookie


def refresh_tokens(session: Session) -> list[RefreshToken]:
    # Scope to the test user: the database may hold other accounts' sessions.
    return list(
        session.scalars(select(RefreshToken).join(User).where(User.email.like("%@example.com")))
    )


# Login success


def test_login_returns_access_token_and_hashed_refresh_token(
    client: TestClient, db_session: Session, settings: Settings, password_hash: str
) -> None:
    user = create_user(db_session, password_hash)

    response = login(client)

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"access_token", "token_type", "expires_in"}
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 15 * 60
    assert response.headers["cache-control"] == "no-store"

    claims = decode_access_token(body["access_token"], settings=settings)
    assert claims.sub == user.id
    assert claims.exp - claims.iat == timedelta(minutes=15)

    raw_refresh = refresh_cookie(response)["refresh_token"].value
    [stored] = refresh_tokens(db_session)
    assert stored.user_id == user.id
    assert stored.token_hash == hash_opaque_token(raw_refresh)
    assert raw_refresh not in {stored.token_hash, str(stored.id), str(stored.family_id)}
    assert stored.used_at is None and stored.revoked_at is None
    lifetime = stored.expires_at - datetime.now(UTC)
    assert timedelta(days=29, hours=23) < lifetime <= timedelta(days=30)


def test_refresh_cookie_has_secure_default_attributes(
    client: TestClient, db_session: Session, password_hash: str
) -> None:
    create_user(db_session, password_hash)

    response = login(client)

    header = response.headers["set-cookie"]
    morsel = refresh_cookie(response)["refresh_token"]
    assert morsel["httponly"] is True
    assert morsel["secure"] is True
    assert morsel["samesite"].lower() == "lax"
    assert morsel["path"] == "/api/v1/auth"
    assert morsel["max-age"] == str(30 * 24 * 60 * 60)
    assert "domain" not in header.lower()


def test_refresh_cookie_attributes_follow_configuration(
    db_session: Session, settings: Settings, password_hash: str
) -> None:
    create_user(db_session, password_hash)
    custom = settings.model_copy(
        update={
            "refresh_cookie_name": "app_refresh",
            "refresh_cookie_path": "/custom/auth",
            "refresh_cookie_domain": "example.com",
            "refresh_cookie_secure": False,
            "refresh_cookie_samesite": "strict",
            "refresh_token_ttl_days": 7,
        }
    )
    application = create_app(custom)
    application.dependency_overrides[database.get_db_session] = lambda: db_session
    application.dependency_overrides[get_email_dispatcher] = lambda: FakeDispatcher()

    with TestClient(application) as client:
        response = login(client)

    morsel = refresh_cookie(response)["app_refresh"]
    assert morsel["path"] == "/custom/auth"
    assert morsel["domain"] == "example.com"
    assert morsel["secure"] == ""
    assert morsel["samesite"].lower() == "strict"
    assert morsel["max-age"] == str(7 * 24 * 60 * 60)


def test_login_normalizes_email(
    client: TestClient, db_session: Session, password_hash: str
) -> None:
    create_user(db_session, password_hash)

    assert login(client, email="  JANE@Example.com ").status_code == 200


def test_each_login_starts_a_new_token_family(
    client: TestClient, db_session: Session, password_hash: str
) -> None:
    create_user(db_session, password_hash)

    login(client)
    login(client)

    first, second = refresh_tokens(db_session)
    assert first.family_id != second.family_id


# Login failures


@pytest.mark.parametrize(
    ("email", "password", "user_options"),
    [
        (EMAIL, "wrong password value", {}),
        ("nobody@example.com", PASSWORD, {}),
        (EMAIL, "wrong password value", {"is_verified": False}),
        (EMAIL, "wrong password value", {"is_active": False}),
    ],
    ids=["wrong-password", "unknown-email", "unverified-wrong-password", "inactive-wrong-password"],
)
def test_credential_failures_are_generic(
    client: TestClient,
    db_session: Session,
    password_hash: str,
    email: str,
    password: str,
    user_options: dict[str, Any],
) -> None:
    create_user(db_session, password_hash, **user_options)

    response = login(client, email=email, password=password)

    assert response.status_code == 401
    assert response.json() == INVALID_CREDENTIALS
    assert "set-cookie" not in response.headers
    assert refresh_tokens(db_session) == []


@pytest.mark.parametrize(
    ("user_options", "code"),
    [({"is_verified": False}, "email_not_verified"), ({"is_active": False}, "account_disabled")],
)
def test_account_state_is_revealed_only_with_correct_password(
    client: TestClient,
    db_session: Session,
    password_hash: str,
    user_options: dict[str, Any],
    code: str,
) -> None:
    create_user(db_session, password_hash, **user_options)

    response = login(client)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == code
    assert "set-cookie" not in response.headers
    assert refresh_tokens(db_session) == []


def test_unknown_email_still_performs_password_verification(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def spy(password: str, password_hash: str) -> bool:
        calls.append(password_hash)
        return verify_password(password, password_hash)

    monkeypatch.setattr("app.auth.service.verify_password", spy)

    response = login(client, email="nobody@example.com")

    assert response.status_code == 401
    [checked_hash] = calls
    assert checked_hash.startswith("$argon2")


def test_login_never_logs_password_or_refresh_token(
    client: TestClient,
    db_session: Session,
    password_hash: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    create_user(db_session, password_hash)

    with caplog.at_level(logging.DEBUG):
        response = login(client)
        login(client, password="another wrong password")

    assert caplog.text
    assert PASSWORD not in caplog.text
    assert "another wrong password" not in caplog.text
    assert refresh_cookie(response)["refresh_token"].value not in caplog.text
    assert response.json()["access_token"] not in caplog.text


# /users/me


@pytest.fixture
def verified_user(db_session: Session, password_hash: str) -> Iterator[User]:
    yield create_user(db_session, password_hash)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_me_returns_profile_for_valid_token(client: TestClient, verified_user: User) -> None:
    access_token = login(client).json()["access_token"]

    response = client.get(ME, headers=bearer(access_token))

    assert response.status_code == 200
    assert response.json() == {
        "id": str(verified_user.id),
        "email": EMAIL,
        "is_verified": True,
        "created_at": verified_user.created_at.isoformat().replace("+00:00", "Z"),
        "roles": ["user"],
        "effective_permissions": ["profile:read"],
    }


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Basic amFuZTpwYXNzd29yZA=="}, {"Authorization": "Bearer"}],
    ids=["missing", "wrong-scheme", "empty-bearer"],
)
def test_me_requires_bearer_credentials(client: TestClient, headers: dict[str, str]) -> None:
    response = client.get(ME, headers=headers)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"
    assert response.headers["www-authenticate"] == "Bearer"


def invalid_tokens(settings: Settings, user: User) -> dict[str, str]:
    key = settings.secret_key.get_secret_value() if settings.secret_key else ""
    now = datetime.now(UTC)
    valid_claims = {"sub": str(user.id), "iat": now, "exp": now + timedelta(minutes=5)}
    return {
        "expired": create_access_token(
            user.id, settings=settings, issued_at=now - timedelta(minutes=16)
        ),
        "wrong-signature": jwt.encode(
            {**valid_claims, "jti": str(uuid4())}, "another-key-" + "y" * 32, algorithm="HS256"
        ),
        "missing-jti": jwt.encode(valid_claims, key, algorithm="HS256"),
        "alg-none": jwt.encode({**valid_claims, "jti": str(uuid4())}, None, algorithm="none"),
        "malformed": "not.a.jwt",
        "unknown-user": create_access_token(uuid4(), settings=settings),
    }


@pytest.mark.parametrize(
    "case",
    ["expired", "wrong-signature", "missing-jti", "alg-none", "malformed", "unknown-user"],
)
def test_me_rejects_invalid_access_tokens(
    client: TestClient, settings: Settings, verified_user: User, case: str
) -> None:
    token = invalid_tokens(settings, verified_user)[case]

    response = client.get(ME, headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'


@pytest.mark.parametrize("change", [{"is_active": False}, {"is_verified": False}])
def test_me_rejects_token_after_account_state_changes(
    client: TestClient, db_session: Session, verified_user: User, change: dict[str, bool]
) -> None:
    access_token = login(client).json()["access_token"]
    for field, value in change.items():
        setattr(verified_user, field, value)
    db_session.flush()

    response = client.get(ME, headers=bearer(access_token))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"
