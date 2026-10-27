"""Predictable authentication failures."""

from http import HTTPStatus

from app.core.exceptions import AppError, ServiceUnavailableError


class EmailAlreadyRegisteredError(AppError):
    status_code = HTTPStatus.CONFLICT
    code = "email_already_registered"
    message = "An account with this email address already exists."


class InvalidActionTokenError(AppError):
    status_code = HTTPStatus.BAD_REQUEST
    code = "invalid_token"
    message = "The token is invalid or has expired."


class VerificationEmailUnavailableError(ServiceUnavailableError):
    code = "verification_email_unavailable"
    message = (
        "The account was created, but the verification email could not be sent. "
        "Request a new verification email shortly."
    )


class InvalidCredentialsError(AppError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "invalid_credentials"
    message = "Email or password is incorrect."


class EmailNotVerifiedError(AppError):
    """Only raised after the client has proven knowledge of the password."""

    status_code = HTTPStatus.FORBIDDEN
    code = "email_not_verified"
    message = "Verify your email address before logging in."


class AccountDisabledError(AppError):
    """Only raised after the client has proven knowledge of the password."""

    status_code = HTTPStatus.FORBIDDEN
    code = "account_disabled"
    message = "This account has been disabled."


class NotAuthenticatedError(AppError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "not_authenticated"
    message = "Authentication is required."
    headers = {"WWW-Authenticate": "Bearer"}


class AccessTokenRejectedError(AppError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "invalid_token"
    message = "The access token is invalid or has expired."
    headers = {"WWW-Authenticate": 'Bearer error="invalid_token"'}


class InvalidRefreshTokenError(AppError):
    """Covers missing, unknown, expired, replayed, and revoked refresh tokens alike."""

    status_code = HTTPStatus.UNAUTHORIZED
    code = "invalid_refresh_token"
    message = "The session has expired. Please log in again."
