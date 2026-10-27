"""Authentication API schemas."""

from typing import Literal

from pydantic import BaseModel, Field, SecretStr

from app.users.schemas import NormalizedEmail

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
# Opaque tokens are 43 characters; the bound only rejects absurd inputs early.
TOKEN_MAX_LENGTH = 256


class RegisterRequest(BaseModel):
    email: NormalizedEmail
    password: SecretStr = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)


class VerifyEmailRequest(BaseModel):
    token: SecretStr = Field(min_length=1, max_length=TOKEN_MAX_LENGTH)


class ResendVerificationRequest(BaseModel):
    email: NormalizedEmail


class LoginRequest(BaseModel):
    email: NormalizedEmail
    # No minimum: login must not reveal the registration policy. The maximum
    # bounds Argon2 work for oversized inputs.
    password: SecretStr = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class TokenResponse(BaseModel):
    """A short-lived access token. The refresh token is sent only as a cookie."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class ForgotPasswordRequest(BaseModel):
    email: NormalizedEmail


class ResetPasswordRequest(BaseModel):
    token: SecretStr = Field(min_length=1, max_length=TOKEN_MAX_LENGTH)
    new_password: SecretStr = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)


class MessageResponse(BaseModel):
    """A human-readable confirmation for actions without a resource body."""

    message: str
