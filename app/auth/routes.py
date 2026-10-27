"""Authentication HTTP endpoints."""

from typing import Any

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from app.auth.exceptions import InvalidRefreshTokenError
from app.auth.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    TokenResponse,
    VerifyEmailRequest,
)
from app.auth.service import AuthServiceDep, IssuedTokens
from app.core.config import Settings
from app.core.dependencies import SettingsDep
from app.core.exceptions import ErrorResponse, error_response
from app.users.schemas import UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])

VALIDATION_ERROR: dict[int | str, dict[str, Any]] = {
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse},
}
RESEND_VERIFICATION_MESSAGE = (
    "If an unverified account exists for this email address, a new verification email "
    "has been sent."
)


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=UserResponse,
    responses={
        status.HTTP_409_CONFLICT: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
        **VALIDATION_ERROR,
    },
)
def register(payload: RegisterRequest, service: AuthServiceDep) -> UserResponse:
    """Create an unverified account and send a verification email."""
    user = service.register(payload.email, payload.password.get_secret_value())
    return UserResponse.model_validate(user)


@router.post(
    "/verify-email",
    response_model=MessageResponse,
    responses={status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse}, **VALIDATION_ERROR},
)
def verify_email(payload: VerifyEmailRequest, service: AuthServiceDep) -> MessageResponse:
    """Consume a single-use email-verification token."""
    service.verify_email(payload.token.get_secret_value())
    return MessageResponse(message="Your email address has been verified.")


@router.post(
    "/resend-verification",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=MessageResponse,
    responses=VALIDATION_ERROR,
)
def resend_verification(
    payload: ResendVerificationRequest, service: AuthServiceDep
) -> MessageResponse:
    """Send a fresh verification email without revealing whether the account exists."""
    service.resend_verification(payload.email)
    return MessageResponse(message=RESEND_VERIFICATION_MESSAGE)


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
        **VALIDATION_ERROR,
    },
)
def login(
    payload: LoginRequest,
    response: Response,
    service: AuthServiceDep,
    settings: SettingsDep,
) -> TokenResponse:
    """Return an access token and set the refresh-token cookie."""
    tokens = service.login(payload.email, payload.password.get_secret_value())
    return token_response(response, settings, tokens)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    responses={status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse}},
)
def refresh(
    request: Request,
    response: Response,
    service: AuthServiceDep,
    settings: SettingsDep,
) -> TokenResponse | JSONResponse:
    """Rotate the refresh-token cookie and return a new access token.

    Every failure clears the cookie so the browser stops presenting a dead token.
    """
    try:
        tokens = service.refresh(request.cookies.get(settings.refresh_cookie_name))
    except InvalidRefreshTokenError as error:
        failure = error_response(error.status_code, error.code, error.message)
        clear_refresh_cookie(failure, settings)
        failure.headers["Cache-Control"] = "no-store"
        return failure
    return token_response(response, settings, tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, service: AuthServiceDep, settings: SettingsDep) -> Response:
    """Revoke the current session family and expire the refresh-token cookie."""
    service.logout(request.cookies.get(settings.refresh_cookie_name))
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_refresh_cookie(response, settings)
    return response


FORGOT_PASSWORD_MESSAGE = (
    "If an account exists for this email address, a password-reset email has been sent."
)


@router.post(
    "/forgot-password",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=MessageResponse,
    responses=VALIDATION_ERROR,
)
def forgot_password(payload: ForgotPasswordRequest, service: AuthServiceDep) -> MessageResponse:
    """Send a password-reset email without revealing whether the account exists."""
    service.forgot_password(payload.email)
    return MessageResponse(message=FORGOT_PASSWORD_MESSAGE)


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    responses={status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse}, **VALIDATION_ERROR},
)
def reset_password(
    payload: ResetPasswordRequest,
    response: Response,
    service: AuthServiceDep,
    settings: SettingsDep,
) -> MessageResponse:
    """Set a new password with a single-use reset token and sign out every session."""
    service.reset_password(
        payload.token.get_secret_value(), payload.new_password.get_secret_value()
    )
    clear_refresh_cookie(response, settings)
    return MessageResponse(message="Your password has been reset. Please log in again.")


def token_response(response: Response, settings: Settings, tokens: IssuedTokens) -> TokenResponse:
    set_refresh_cookie(response, settings, tokens.refresh_token, tokens.refresh_token_max_age)
    response.headers["Cache-Control"] = "no-store"
    return TokenResponse(
        access_token=tokens.access_token, expires_in=tokens.access_token_expires_in
    )


def set_refresh_cookie(response: Response, settings: Settings, token: str, max_age: int) -> None:
    """Attach the refresh token using the configured cookie attributes."""
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=max_age,
        path=settings.refresh_cookie_path,
        domain=settings.refresh_cookie_domain,
        secure=settings.refresh_cookie_secure,
        httponly=True,
        samesite=settings.refresh_cookie_samesite,
    )


def clear_refresh_cookie(response: Response, settings: Settings) -> None:
    """Expire the cookie; attributes must match the ones it was set with."""
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=settings.refresh_cookie_path,
        domain=settings.refresh_cookie_domain,
        secure=settings.refresh_cookie_secure,
        httponly=True,
        samesite=settings.refresh_cookie_samesite,
    )
