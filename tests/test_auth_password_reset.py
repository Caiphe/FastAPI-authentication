"""Forgot-password and reset-password flows."""

import logging
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.models import ActionToken, ActionTokenPurpose, RefreshToken
from app.core.security import generate_opaque_token, hash_opaque_token, verify_password
from app.core.security import hash_password as real_hash_password
from app.users.models import User
from tests.conftest import FakeDispatcher

pytestmark = pytest.mark.integration

FORGOT = "/api/v1/auth/forgot-password"
RESET = "/api/v1/auth/reset-password"
LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
EMAIL = "jane@example.com"
OLD_PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a brand new passphrase 2026"
NEUTRAL_FORGOT = {
    "message": "If an account exists for this email address, a password-reset email has been sent."
}


@pytest.fixture(scope="module")
def password_hash() -> str:
    return real_hash_password(OLD_PASSWORD)


def create_user(
    session: Session, password_hash: str, *, is_verified: bool = True, is_active: bool = True
) -> User:
    user = User(
        email=EMAIL, hashed_password=password_hash, is_verified=is_verified, is_active=is_active
    )
    session.add(user)
    session.flush()
    return user


@pytest.fixture
def user(db_session: Session, password_hash: str) -> User:
    return create_user(db_session, password_hash)


# TestClient returns an httpx or httpx2 response depending on what is installed.
def forgot(client: TestClient, email: str = EMAIL) -> Any:
    return client.post(FORGOT, json={"email": email})


def reset(client: TestClient, token: str, new_password: str = NEW_PASSWORD) -> Any:
    return client.post(RESET, json={"token": token, "new_password": new_password})


def login(client: TestClient, password: str) -> Any:
    return client.post(LOGIN, json={"email": EMAIL, "password": password})


def reset_tokens(session: Session, user: User) -> list[ActionToken]:
    session.expire_all()
    return list(
        session.scalars(
            select(ActionToken).where(
                ActionToken.user_id == user.id,
                ActionToken.purpose == ActionTokenPurpose.PASSWORD_RESET,
            )
        )
    )


def requested_token(client: TestClient, dispatcher: FakeDispatcher) -> str:
    assert forgot(client).status_code == 202
    queued = dispatcher.queued[-1]
    assert queued.purpose == "password_reset"
    return queued.token


# Forgot password


def test_forgot_password_stores_hashed_token_and_queues_email_after_commit(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher, user: User
) -> None:
    response = forgot(client, "  JANE@Example.com ")

    assert response.status_code == 202
    assert response.json() == NEUTRAL_FORGOT
    [queued] = dispatcher.queued
    assert queued.purpose == "password_reset"
    assert queued.transaction_open is False
    [token] = reset_tokens(db_session, user)
    assert token.id == queued.action_token_id
    assert token.token_hash == hash_opaque_token(queued.token)
    assert token.token_hash != queued.token
    lifetime = token.expires_at - datetime.now(UTC)
    assert timedelta(minutes=59) < lifetime <= timedelta(minutes=60)


@pytest.mark.parametrize(
    "setup",
    ["unknown", "inactive"],
)
def test_forgot_password_is_neutral_for_ineligible_accounts(
    client: TestClient,
    db_session: Session,
    dispatcher: FakeDispatcher,
    password_hash: str,
    setup: str,
) -> None:
    if setup == "inactive":
        create_user(db_session, password_hash, is_active=False)
    # Scope to this test: the database may hold other accounts' tokens.
    existing = set(db_session.scalars(select(ActionToken.id)))

    response = forgot(client)

    assert response.status_code == 202
    assert response.json() == NEUTRAL_FORGOT
    assert dispatcher.queued == []
    assert set(db_session.scalars(select(ActionToken.id))) == existing


def test_forgot_password_replaces_prior_reset_tokens(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher, user: User
) -> None:
    first = requested_token(client, dispatcher)
    second = requested_token(client, dispatcher)

    [stored] = reset_tokens(db_session, user)
    assert stored.token_hash == hash_opaque_token(second)
    assert reset(client, first).status_code == 400
    assert reset(client, second).status_code == 200


def test_forgot_password_stays_neutral_when_broker_is_unavailable(
    client: TestClient,
    dispatcher: FakeDispatcher,
    user: User,
    caplog: pytest.LogCaptureFixture,
) -> None:
    dispatcher.fail = True

    response = forgot(client)

    assert response.status_code == 202
    assert response.json() == NEUTRAL_FORGOT
    assert "could not be queued" in caplog.text


# Reset password


def test_reset_password_changes_password_and_consumes_token(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher, user: User
) -> None:
    token = requested_token(client, dispatcher)

    response = reset(client, token)

    assert response.status_code == 200
    assert response.json() == {"message": "Your password has been reset. Please log in again."}
    db_session.expire_all()
    assert verify_password(NEW_PASSWORD, user.hashed_password)
    assert not verify_password(OLD_PASSWORD, user.hashed_password)
    [stored] = reset_tokens(db_session, user)
    assert stored.used_at is not None

    assert login(client, OLD_PASSWORD).status_code == 401
    assert login(client, NEW_PASSWORD).status_code == 200


def test_reset_password_revokes_every_session_and_clears_cookie(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher, user: User
) -> None:
    sessions = []
    for _ in range(2):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(login(client, OLD_PASSWORD).headers["set-cookie"])
        sessions.append(cookie["refresh_token"].value)
    token = requested_token(client, dispatcher)

    response = reset(client, token)

    assert response.status_code == 200
    cleared: SimpleCookie = SimpleCookie()
    cleared.load(response.headers["set-cookie"])
    assert cleared["refresh_token"].value == ""
    assert cleared["refresh_token"]["max-age"] == "0"
    assert cleared["refresh_token"]["path"] == "/api/v1/auth"

    db_session.expire_all()
    stored = list(db_session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)))
    assert len({t.family_id for t in stored}) == 2
    assert all(t.revoked_at is not None for t in stored)
    for refresh_token in sessions:
        response = client.post(REFRESH, headers={"Cookie": f"refresh_token={refresh_token}"})
        assert response.status_code == 401


def test_reset_password_verifies_unverified_account(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher, password_hash: str
) -> None:
    user = create_user(db_session, password_hash, is_verified=False)
    db_session.add(
        ActionToken(
            user_id=user.id,
            purpose=ActionTokenPurpose.EMAIL_VERIFICATION,
            token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    db_session.flush()
    token = requested_token(client, dispatcher)

    assert reset(client, token).status_code == 200

    db_session.expire_all()
    assert user.is_verified is True
    remaining = db_session.scalars(
        select(ActionToken).where(
            ActionToken.user_id == user.id,
            ActionToken.purpose == ActionTokenPurpose.EMAIL_VERIFICATION,
        )
    ).all()
    assert remaining == []
    assert login(client, NEW_PASSWORD).status_code == 200


def test_reset_token_cannot_be_reused(
    client: TestClient, dispatcher: FakeDispatcher, user: User
) -> None:
    token = requested_token(client, dispatcher)
    assert reset(client, token).status_code == 200

    response = reset(client, token, "yet another passphrase!!")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_token"
    assert login(client, NEW_PASSWORD).status_code == 200


def test_reset_token_expires(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher, user: User
) -> None:
    token = requested_token(client, dispatcher)
    [stored] = reset_tokens(db_session, user)
    stored.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()

    response = reset(client, token)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_token"
    assert login(client, OLD_PASSWORD).status_code == 200


def test_reset_rejects_unknown_and_verification_tokens(
    client: TestClient, db_session: Session, user: User
) -> None:
    verification_token = generate_opaque_token()
    db_session.add(
        ActionToken(
            user_id=user.id,
            purpose=ActionTokenPurpose.EMAIL_VERIFICATION,
            token_hash=hash_opaque_token(verification_token),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    db_session.flush()

    for token in (generate_opaque_token(), verification_token):
        response = reset(client, token)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_token"
    assert login(client, OLD_PASSWORD).status_code == 200


def test_reset_rejects_token_of_disabled_account(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher, user: User
) -> None:
    token = requested_token(client, dispatcher)
    user.is_active = False
    db_session.flush()

    assert reset(client, token).status_code == 400


@pytest.mark.parametrize("new_password", ["x" * 11, "x" * 129])
def test_reset_enforces_password_policy_without_echoing_input(
    client: TestClient, dispatcher: FakeDispatcher, user: User, new_password: str
) -> None:
    token = requested_token(client, dispatcher)

    response = reset(client, token, new_password)

    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["loc"] == ["body", "new_password"]
    assert new_password not in response.text
    assert token not in response.text
    # The token was not consumed by the rejected request.
    assert reset(client, token).status_code == 200


def test_password_reset_never_logs_passwords_or_tokens(
    client: TestClient,
    dispatcher: FakeDispatcher,
    user: User,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        token = requested_token(client, dispatcher)
        reset(client, token)
        reset(client, token)
        login(client, NEW_PASSWORD)

    assert caplog.text
    for secret in (token, hash_opaque_token(token), OLD_PASSWORD, NEW_PASSWORD):
        assert secret not in caplog.text
