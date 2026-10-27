"""Password, opaque-token, and access-token security primitives."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe
from uuid import UUID, uuid4

import jwt
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher
from pydantic import BaseModel, ValidationError, model_validator

from app.core.config import Settings, get_settings

OPAQUE_TOKEN_BYTES = 32
MINIMUM_SIGNING_KEY_LENGTH = 32
REQUIRED_ACCESS_TOKEN_CLAIMS = ["sub", "iat", "exp", "jti"]

password_hasher = PasswordHash((Argon2Hasher(),))


class SecurityConfigurationError(RuntimeError):
    """Raised when security configuration is missing or unsafe."""


class InvalidAccessTokenError(ValueError):
    """Raised when an access token cannot be trusted."""


class AccessTokenClaims(BaseModel):
    """Validated claims carried by an access JWT."""

    sub: UUID
    iat: datetime
    exp: datetime
    jti: UUID

    @model_validator(mode="after")
    def validate_lifetime(self) -> "AccessTokenClaims":
        if self.exp <= self.iat:
            raise ValueError("access token expiration must be after its issue time")
        return self


def hash_password(password: str) -> str:
    """Hash a password with the configured Argon2 hasher."""
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without leaking malformed-hash details."""
    try:
        return password_hasher.verify(password, password_hash)
    except UnknownHashError:
        return False


def generate_opaque_token() -> str:
    """Generate a URL-safe token with 256 bits of entropy."""
    return token_urlsafe(OPAQUE_TOKEN_BYTES)


def hash_opaque_token(token: str) -> str:
    """Create the deterministic digest stored for an opaque token."""
    return sha256(token.encode("utf-8")).hexdigest()


def verify_opaque_token(token: str, expected_hash: str) -> bool:
    """Compare an opaque token with its stored digest in constant time."""
    return compare_digest(hash_opaque_token(token), expected_hash)


def create_access_token(
    subject: UUID,
    *,
    settings: Settings | None = None,
    issued_at: datetime | None = None,
    token_id: UUID | None = None,
) -> str:
    """Create a signed, short-lived JWT for a user."""
    resolved_settings = settings or get_settings()
    signing_key = _get_signing_key(resolved_settings)
    issued = _as_utc(issued_at or datetime.now(UTC))
    expires = issued + timedelta(minutes=resolved_settings.access_token_ttl_minutes)

    payload = {
        "sub": str(subject),
        "iat": issued,
        "exp": expires,
        "jti": str(token_id or uuid4()),
    }
    return jwt.encode(
        payload,
        signing_key,
        algorithm=resolved_settings.jwt_algorithm,
    )


def decode_access_token(
    token: str,
    *,
    settings: Settings | None = None,
) -> AccessTokenClaims:
    """Verify and parse a signed access JWT."""
    resolved_settings = settings or get_settings()
    signing_key = _get_signing_key(resolved_settings)

    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=[resolved_settings.jwt_algorithm],
            options={"require": REQUIRED_ACCESS_TOKEN_CLAIMS},
        )
        return AccessTokenClaims.model_validate(payload)
    except (jwt.InvalidTokenError, ValidationError) as error:
        raise InvalidAccessTokenError("access token is invalid") from error


def _get_signing_key(settings: Settings) -> str:
    secret = settings.secret_key.get_secret_value() if settings.secret_key else ""
    if len(secret) < MINIMUM_SIGNING_KEY_LENGTH:
        raise SecurityConfigurationError(
            "AUTH_SECRET_KEY must contain at least 32 characters before issuing tokens"
        )
    return secret


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("issued_at must be timezone-aware")
    return value.astimezone(UTC)
