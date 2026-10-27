"""Registration, email verification, and resend-verification against PostgreSQL."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.models import ActionToken, ActionTokenPurpose
from app.core.security import generate_opaque_token, hash_opaque_token, verify_password
from app.rbac.models import Role, UserRole
from app.users import repository as user_repository
from app.users.models import User
from tests.conftest import FakeDispatcher

pytestmark = pytest.mark.integration

REGISTER = "/api/v1/auth/register"
VERIFY = "/api/v1/auth/verify-email"
RESEND = "/api/v1/auth/resend-verification"
PASSWORD = "correct horse battery staple"
NEUTRAL_RESEND = {
    "message": (
        "If an unverified account exists for this email address, a new verification email "
        "has been sent."
    )
}


def register(client: TestClient, email: str = "jane@example.com") -> dict[str, object]:
    response = client.post(REGISTER, json={"email": email, "password": PASSWORD})
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def user_by_email(session: Session, email: str) -> User:
    return session.scalars(select(User).where(User.email == email)).one()


def tokens_for(session: Session, user: User) -> list[ActionToken]:
    session.expire_all()
    return list(session.scalars(select(ActionToken).where(ActionToken.user_id == user.id)))


def assert_error(response_json: dict[str, object], code: str) -> None:
    error = response_json["error"]
    assert isinstance(error, dict)
    assert error["code"] == code


# Registration


def test_register_creates_unverified_user_and_queues_email_after_commit(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    body = register(client, "  Jane.Doe@Example.COM ")

    assert set(body) == {"id", "email", "is_verified", "created_at"}
    assert body["email"] == "jane.doe@example.com"
    assert body["is_verified"] is False

    user = user_by_email(db_session, "jane.doe@example.com")
    assert user.is_active is True
    assert user.hashed_password.startswith("$argon2")
    assert verify_password(PASSWORD, user.hashed_password)

    [queued] = dispatcher.queued
    [token] = tokens_for(db_session, user)
    assert queued.purpose == "email_verification"
    assert queued.action_token_id == token.id
    assert queued.transaction_open is False
    assert token.token_hash == hash_opaque_token(queued.token)
    assert token.token_hash != queued.token
    assert token.used_at is None
    lifetime = token.expires_at - datetime.now(UTC)
    assert timedelta(hours=23, minutes=59) < lifetime <= timedelta(hours=24)


def test_register_assigns_the_default_user_role(client: TestClient, db_session: Session) -> None:
    register(client)

    user = user_by_email(db_session, "jane@example.com")
    [assignment] = db_session.scalars(select(UserRole).where(UserRole.user_id == user.id)).all()
    assert assignment.role.name == "user"
    assert assignment.assigned_by_user_id is None


def test_register_rolls_back_everything_when_default_role_is_missing(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    db_session.execute(delete(Role).where(Role.name == "user"))
    db_session.commit()

    response = client.post(REGISTER, json={"email": "jane@example.com", "password": PASSWORD})

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "configuration_error",
            "message": "The service is not configured correctly.",
            "details": None,
        }
    }
    db_session.expire_all()
    assert db_session.scalars(select(User).where(User.email == "jane@example.com")).all() == []
    assert dispatcher.queued == []


@pytest.mark.parametrize("password_length", [12, 128])
def test_register_accepts_password_length_boundaries(
    client: TestClient, password_length: int
) -> None:
    response = client.post(
        REGISTER, json={"email": "jane@example.com", "password": "p" * password_length}
    )

    assert response.status_code == 201


@pytest.mark.parametrize("variant", ["jane@example.com", "JANE@Example.com", " jane@EXAMPLE.COM"])
def test_duplicate_registration_returns_conflict(
    client: TestClient, dispatcher: FakeDispatcher, variant: str
) -> None:
    register(client, "jane@example.com")

    response = client.post(REGISTER, json={"email": variant, "password": PASSWORD})

    assert response.status_code == 409
    assert_error(response.json(), "email_already_registered")
    assert len(dispatcher.queued) == 1


def test_concurrent_duplicate_registration_maps_integrity_error_to_conflict(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    register(client, "jane@example.com")
    # Simulate a concurrent request that passed the existence check first.
    monkeypatch.setattr(user_repository, "get_user_by_email", lambda session, email: None)

    response = client.post(REGISTER, json={"email": "jane@example.com", "password": PASSWORD})

    assert response.status_code == 409
    assert_error(response.json(), "email_already_registered")
    assert user_by_email(db_session, "jane@example.com") is not None


def test_database_rejects_case_variant_duplicates(db_session: Session) -> None:
    db_session.add(User(email="jane@example.com", hashed_password="hash"))
    db_session.flush()

    with db_session.begin_nested(), pytest.raises(IntegrityError, match="uq_users_email_lower"):
        db_session.add(User(email="JANE@example.com", hashed_password="hash"))
        db_session.flush()


def test_broker_outage_keeps_account_and_allows_resend(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    dispatcher.fail = True

    response = client.post(REGISTER, json={"email": "jane@example.com", "password": PASSWORD})

    assert response.status_code == 503
    assert_error(response.json(), "verification_email_unavailable")
    user = user_by_email(db_session, "jane@example.com")
    assert len(tokens_for(db_session, user)) == 1

    dispatcher.fail = False
    resend = client.post(RESEND, json={"email": "jane@example.com"})

    assert resend.status_code == 202
    [queued] = dispatcher.queued
    [token] = tokens_for(db_session, user)
    assert token.id == queued.action_token_id


# Email verification


def test_verify_email_consumes_token_once(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    register(client)
    [queued] = dispatcher.queued

    first = client.post(VERIFY, json={"token": queued.token})
    second = client.post(VERIFY, json={"token": queued.token})

    assert first.status_code == 200
    assert first.json() == {"message": "Your email address has been verified."}
    assert second.status_code == 400
    assert_error(second.json(), "invalid_token")
    user = user_by_email(db_session, "jane@example.com")
    assert user.is_verified is True
    [token] = tokens_for(db_session, user)
    assert token.used_at is not None


def test_verify_email_rejects_expired_token(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    register(client)
    [queued] = dispatcher.queued
    token = db_session.get(ActionToken, queued.action_token_id)
    assert token is not None
    token.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.flush()

    response = client.post(VERIFY, json={"token": queued.token})

    assert response.status_code == 400
    assert_error(response.json(), "invalid_token")
    assert user_by_email(db_session, "jane@example.com").is_verified is False


def test_verify_email_rejects_unknown_token(client: TestClient) -> None:
    response = client.post(VERIFY, json={"token": generate_opaque_token()})

    assert response.status_code == 400
    assert_error(response.json(), "invalid_token")


def test_verify_email_rejects_password_reset_token(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    register(client)
    user = user_by_email(db_session, "jane@example.com")
    raw_token = generate_opaque_token()
    db_session.add(
        ActionToken(
            user_id=user.id,
            purpose=ActionTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(raw_token),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    db_session.flush()

    response = client.post(VERIFY, json={"token": raw_token})

    assert response.status_code == 400
    assert user_by_email(db_session, "jane@example.com").is_verified is False


def test_verify_email_rejects_token_of_inactive_user(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    register(client)
    user_by_email(db_session, "jane@example.com").is_active = False
    db_session.flush()

    response = client.post(VERIFY, json={"token": dispatcher.queued[0].token})

    assert response.status_code == 400


# Resend verification


def test_resend_replaces_prior_tokens(
    client: TestClient, db_session: Session, dispatcher: FakeDispatcher
) -> None:
    register(client)

    response = client.post(RESEND, json={"email": "JANE@example.com"})

    assert response.status_code == 202
    assert response.json() == NEUTRAL_RESEND
    original, replacement = dispatcher.queued
    assert replacement.transaction_open is False
    [stored] = tokens_for(db_session, user_by_email(db_session, "jane@example.com"))
    assert stored.id == replacement.action_token_id

    assert client.post(VERIFY, json={"token": original.token}).status_code == 400
    assert client.post(VERIFY, json={"token": replacement.token}).status_code == 200


def test_resend_is_neutral_for_unknown_email(
    client: TestClient, dispatcher: FakeDispatcher
) -> None:
    response = client.post(RESEND, json={"email": "nobody@example.com"})

    assert response.status_code == 202
    assert response.json() == NEUTRAL_RESEND
    assert dispatcher.queued == []


def test_resend_is_neutral_for_verified_account(
    client: TestClient, dispatcher: FakeDispatcher
) -> None:
    register(client)
    client.post(VERIFY, json={"token": dispatcher.queued[0].token})

    response = client.post(RESEND, json={"email": "jane@example.com"})

    assert response.status_code == 202
    assert response.json() == NEUTRAL_RESEND
    assert len(dispatcher.queued) == 1


def test_resend_stays_neutral_when_broker_is_unavailable(
    client: TestClient, dispatcher: FakeDispatcher, caplog: pytest.LogCaptureFixture
) -> None:
    register(client)
    dispatcher.fail = True

    response = client.post(RESEND, json={"email": "jane@example.com"})

    assert response.status_code == 202
    assert response.json() == NEUTRAL_RESEND
    assert "could not be queued" in caplog.text
