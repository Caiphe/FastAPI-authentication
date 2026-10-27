"""Security primitive tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from app.core.config import Environment, Settings
from app.core.security import (
    InvalidAccessTokenError,
    SecurityConfigurationError,
    create_access_token,
    decode_access_token,
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    verify_opaque_token,
    verify_password,
)

SIGNING_KEY = "a" * 32


def security_settings(secret_key: str = SIGNING_KEY) -> Settings:
    return Settings.model_validate(
        {
            "environment": Environment.TEST,
            "secret_key": secret_key,
        }
    )


def test_password_is_hashed_with_argon2_and_can_be_verified() -> None:
    password = "correct horse battery staple"

    password_hash = hash_password(password)

    assert password_hash != password
    assert password_hash.startswith("$argon2")
    assert verify_password(password, password_hash)
    assert not verify_password("incorrect password", password_hash)


def test_password_verification_rejects_unknown_hash() -> None:
    assert not verify_password("password", "not-a-supported-password-hash")


def test_opaque_tokens_are_random_and_only_their_digest_matches() -> None:
    first_token = generate_opaque_token()
    second_token = generate_opaque_token()
    token_hash = hash_opaque_token(first_token)

    assert first_token != second_token
    assert len(token_hash) == 64
    assert first_token not in token_hash
    assert verify_opaque_token(first_token, token_hash)
    assert not verify_opaque_token(second_token, token_hash)


def test_access_token_contains_required_claims_and_default_lifetime() -> None:
    settings = security_settings()
    subject = uuid4()
    token_id = uuid4()
    issued_at = datetime.now(UTC).replace(microsecond=0)

    token = create_access_token(
        subject,
        settings=settings,
        issued_at=issued_at,
        token_id=token_id,
    )
    claims = decode_access_token(token, settings=settings)

    assert claims.sub == subject
    assert claims.jti == token_id
    assert claims.iat == issued_at
    assert claims.exp - claims.iat == timedelta(minutes=15)


def test_access_token_carries_only_identity_claims() -> None:
    settings = security_settings()
    token = create_access_token(uuid4(), settings=settings)

    payload = jwt.decode(token, options={"verify_signature": False})

    # Authorization is resolved from the database; tokens never carry roles.
    assert set(payload) == {"sub", "iat", "exp", "jti"}


def test_expired_access_token_is_rejected() -> None:
    settings = security_settings()
    token = create_access_token(
        uuid4(),
        settings=settings,
        issued_at=datetime.now(UTC) - timedelta(minutes=16),
    )

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, settings=settings)


@pytest.mark.parametrize("token", ["not-a-jwt", "", "one.two.three"])
def test_malformed_access_token_is_rejected(token: str) -> None:
    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, settings=security_settings())


def test_access_token_signed_with_another_key_is_rejected() -> None:
    token = create_access_token(uuid4(), settings=security_settings("a" * 32))

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, settings=security_settings("b" * 32))


def test_access_token_missing_required_claim_is_rejected() -> None:
    settings = security_settings()
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        },
        SIGNING_KEY,
        algorithm="HS256",
    )

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, settings=settings)


def test_access_token_rejects_short_signing_key() -> None:
    with pytest.raises(SecurityConfigurationError, match="AUTH_SECRET_KEY"):
        create_access_token(uuid4(), settings=security_settings("too-short"))


def test_access_token_requires_timezone_aware_issue_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        create_access_token(
            uuid4(),
            settings=security_settings(),
            issued_at=datetime.now(),
        )
