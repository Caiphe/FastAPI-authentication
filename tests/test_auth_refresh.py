"""Refresh-token rotation, family reuse detection, and logout."""

import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.auth.exceptions import InvalidRefreshTokenError
from app.auth.models import RefreshToken
from app.auth.service import AuthService, IssuedTokens
from app.core import database
from app.core.config import Settings
from app.core.security import decode_access_token, generate_opaque_token, hash_opaque_token
from app.core.security import hash_password as real_hash_password
from app.users.models import User
from tests.conftest import FakeDispatcher

pytestmark = pytest.mark.integration

LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
LOGOUT = "/api/v1/auth/logout"
ME = "/api/v1/users/me"
EMAIL = "jane@example.com"
PASSWORD = "correct horse battery staple"
INVALID_REFRESH = {
    "error": {
        "code": "invalid_refresh_token",
        "message": "The session has expired. Please log in again.",
        "details": None,
    }
}


@pytest.fixture(scope="module")
def password_hash() -> str:
    return real_hash_password(PASSWORD)


@pytest.fixture
def user(db_session: Session, password_hash: str) -> User:
    account = User(email=EMAIL, hashed_password=password_hash, is_verified=True)
    db_session.add(account)
    db_session.flush()
    return account


# TestClient returns an httpx or httpx2 response depending on what is installed.
def login(client: TestClient) -> str:
    response = client.post(LOGIN, json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return cookie_value(response)


def refresh(client: TestClient, raw_token: str | None) -> Any:
    headers = {"Cookie": f"refresh_token={raw_token}"} if raw_token is not None else {}
    return client.post(REFRESH, headers=headers)


def logout(client: TestClient, raw_token: str | None) -> Any:
    headers = {"Cookie": f"refresh_token={raw_token}"} if raw_token is not None else {}
    return client.post(LOGOUT, headers=headers)


def set_cookie(response: Any) -> SimpleCookie:
    cookie: SimpleCookie = SimpleCookie()
    cookie.load(response.headers["set-cookie"])
    return cookie


def cookie_value(response: Any) -> str:
    return set_cookie(response)["refresh_token"].value


def stored(session: Session, raw_token: str) -> RefreshToken:
    session.expire_all()
    return session.scalars(
        select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw_token))
    ).one()


def family(session: Session, token: RefreshToken) -> list[RefreshToken]:
    session.expire_all()
    return list(
        session.scalars(select(RefreshToken).where(RefreshToken.family_id == token.family_id))
    )


def assert_cookie_cleared(response: Any) -> None:
    morsel = set_cookie(response)["refresh_token"]
    assert morsel.value == ""
    assert morsel["max-age"] == "0"
    assert morsel["path"] == "/api/v1/auth"
    assert morsel["secure"] is True
    assert morsel["httponly"] is True
    assert morsel["samesite"].lower() == "lax"


def assert_rejected(response: Any) -> None:
    assert response.status_code == 401
    assert response.json() == INVALID_REFRESH
    assert response.headers["cache-control"] == "no-store"
    assert_cookie_cleared(response)


# Rotation


def test_refresh_rotates_token_within_its_family(
    client: TestClient, db_session: Session, settings: Settings, user: User
) -> None:
    original = login(client)

    response = refresh(client, original)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert decode_access_token(body["access_token"], settings=settings).sub == user.id
    assert body["expires_in"] == 900

    rotated = cookie_value(response)
    assert rotated != original
    morsel = set_cookie(response)["refresh_token"]
    assert morsel["httponly"] is True and morsel["secure"] is True
    assert morsel["path"] == "/api/v1/auth"
    assert morsel["max-age"] == str(30 * 24 * 60 * 60)

    old, new = stored(db_session, original), stored(db_session, rotated)
    assert old.family_id == new.family_id
    assert old.used_at is not None and old.replaced_by_id == new.id
    assert old.revoked_at is None
    assert new.used_at is None and new.revoked_at is None
    assert new.token_hash == hash_opaque_token(rotated)


def test_rotation_chain_can_continue(client: TestClient, db_session: Session, user: User) -> None:
    first = token = login(client)
    for _ in range(3):
        response = refresh(client, token)
        assert response.status_code == 200
        token = cookie_value(response)

    # Follow replaced_by links; created_at is shared within the test transaction.
    by_id = {t.id: t for t in family(db_session, stored(db_session, token))}
    chain = [stored(db_session, first)]
    while chain[-1].replaced_by_id is not None:
        chain.append(by_id[chain[-1].replaced_by_id])
    assert len(by_id) == len(chain) == 4
    assert chain[-1].token_hash == hash_opaque_token(token)
    assert [t.used_at is None for t in chain] == [False, False, False, True]


# Reuse detection


def test_replaying_rotated_token_revokes_entire_family(
    client: TestClient, db_session: Session, user: User
) -> None:
    original = login(client)
    rotated = cookie_value(refresh(client, original))

    replay = refresh(client, original)

    assert_rejected(replay)
    assert all(t.revoked_at is not None for t in family(db_session, stored(db_session, original)))
    # The legitimate holder of the newest token is logged out as well.
    assert_rejected(refresh(client, rotated))


def test_reusing_revoked_token_is_rejected_and_family_stays_revoked(
    client: TestClient, db_session: Session, user: User
) -> None:
    token = login(client)
    logout(client, token)

    assert_rejected(refresh(client, token))
    assert stored(db_session, token).revoked_at is not None


def test_reuse_revokes_only_the_affected_family(
    client: TestClient, db_session: Session, user: User
) -> None:
    attacked = login(client)
    other_device = login(client)
    refresh(client, attacked)

    refresh(client, attacked)

    assert stored(db_session, other_device).revoked_at is None
    assert refresh(client, other_device).status_code == 200


# Deterministic failures


@pytest.mark.parametrize(
    "raw_token",
    [None, "", "not-a-real-token", "x" * 5000, generate_opaque_token()],
    ids=["missing", "empty", "malformed", "oversized", "unknown"],
)
def test_refresh_rejects_missing_or_unknown_tokens(
    client: TestClient, user: User, raw_token: str | None
) -> None:
    assert_rejected(refresh(client, raw_token))


def test_refresh_rejects_expired_token_without_revoking_family(
    client: TestClient, db_session: Session, user: User
) -> None:
    token = login(client)
    record = stored(db_session, token)
    record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()

    assert_rejected(refresh(client, token))
    assert stored(db_session, token).revoked_at is None
    assert stored(db_session, token).used_at is None


@pytest.mark.parametrize("change", [{"is_active": False}, {"is_verified": False}])
def test_refresh_rejects_token_of_ineligible_user(
    client: TestClient, db_session: Session, user: User, change: dict[str, bool]
) -> None:
    token = login(client)
    for field, value in change.items():
        setattr(user, field, value)
    db_session.flush()

    assert_rejected(refresh(client, token))


# Logout


def test_logout_revokes_current_family_and_clears_cookie(
    client: TestClient, db_session: Session, user: User
) -> None:
    first = login(client)
    rotated = cookie_value(refresh(client, first))
    other_device = login(client)

    response = logout(client, rotated)

    assert response.status_code == 204
    assert response.content == b""
    assert_cookie_cleared(response)
    assert all(t.revoked_at is not None for t in family(db_session, stored(db_session, rotated)))
    assert stored(db_session, other_device).revoked_at is None
    assert_rejected(refresh(client, rotated))


@pytest.mark.parametrize("raw_token", [None, "unknown-token"], ids=["missing", "unknown"])
def test_logout_without_valid_cookie_still_clears_it(
    client: TestClient, user: User, raw_token: str | None
) -> None:
    response = logout(client, raw_token)

    assert response.status_code == 204
    assert_cookie_cleared(response)


def test_logout_is_idempotent(client: TestClient, user: User) -> None:
    token = login(client)

    assert logout(client, token).status_code == 204
    assert logout(client, token).status_code == 204


# Browser behaviour


def test_browser_cookie_jar_scopes_and_clears_refresh_cookie(
    make_app: Callable[..., FastAPI], db_session: Session, user: User
) -> None:
    with TestClient(make_app(db_session), base_url="https://testserver") as browser:
        access_token = browser.post(LOGIN, json={"email": EMAIL, "password": PASSWORD}).json()[
            "access_token"
        ]

        me = browser.get(ME, headers={"Authorization": f"Bearer {access_token}"})
        assert me.status_code == 200
        assert "cookie" not in me.request.headers  # Path=/api/v1/auth keeps it out

        refreshed = browser.post(REFRESH)
        assert refreshed.status_code == 200
        assert "refresh_token=" in refreshed.request.headers["cookie"]

        assert browser.post(LOGOUT).status_code == 204
        assert browser.cookies.get("refresh_token") is None
        assert browser.post(REFRESH).status_code == 401


# Concurrency


@pytest.fixture
def committed_user(settings: Settings, password_hash: str) -> Iterator[User]:
    email = f"concurrent-{uuid4().hex}@example.com"
    with database.SessionFactory() as session:
        account = User(email=email, hashed_password=password_hash, is_verified=True)
        session.add(account)
        session.commit()
    try:
        yield account
    finally:
        with database.SessionFactory() as session:
            session.execute(delete(User).where(User.email == email))
            session.commit()


def test_concurrent_refresh_with_same_token_rotates_once_and_revokes_family(
    settings: Settings, committed_user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    def service(session: Session) -> AuthService:
        return AuthService(session, settings, FakeDispatcher())

    with database.SessionFactory() as session:
        raw_token = service(session).login(committed_user.email, PASSWORD).refresh_token

    # Widen the race: hold the row lock while the replacement token is generated.
    def slow_token() -> str:
        time.sleep(0.3)
        return generate_opaque_token()

    monkeypatch.setattr("app.auth.service.generate_opaque_token", slow_token)
    barrier = threading.Barrier(2)
    outcomes: list[IssuedTokens | Exception] = []
    lock = threading.Lock()

    def attempt() -> None:
        with database.SessionFactory() as session:
            barrier.wait()
            try:
                result: IssuedTokens | Exception = service(session).refresh(raw_token)
            except Exception as error:
                result = error
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    successes = [o for o in outcomes if isinstance(o, IssuedTokens)]
    failures = [o for o in outcomes if isinstance(o, Exception)]
    assert len(successes) == 1
    assert len(failures) == 1 and isinstance(failures[0], InvalidRefreshTokenError)

    with database.SessionFactory() as session:
        tokens = list(
            session.scalars(select(RefreshToken).where(RefreshToken.user_id == committed_user.id))
        )
    assert len(tokens) == 2
    assert all(t.revoked_at is not None for t in tokens)
