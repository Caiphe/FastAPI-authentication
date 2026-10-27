"""Registration, email verification, login, session refresh, and logout use cases."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import repository as token_repository
from app.auth.dispatch import EmailDispatcher, get_email_dispatcher
from app.auth.exceptions import (
    AccessTokenRejectedError,
    AccountDisabledError,
    EmailAlreadyRegisteredError,
    EmailNotVerifiedError,
    InvalidActionTokenError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    VerificationEmailUnavailableError,
)
from app.auth.models import ActionToken, ActionTokenPurpose, RefreshToken
from app.core.config import Settings
from app.core.dependencies import SessionDep, SettingsDep
from app.core.security import (
    InvalidAccessTokenError,
    create_access_token,
    decode_access_token,
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    verify_password,
)
from app.email.tasks import EmailDispatchError
from app.rbac.exceptions import DefaultRoleMissingError
from app.rbac.service import RbacService
from app.users import repository as user_repository
from app.users.models import User
from app.users.schemas import normalize_email

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    """Tokens issued by login or refresh. ``refresh_token`` is the raw cookie value."""

    access_token: str
    access_token_expires_in: int
    refresh_token: str
    refresh_token_max_age: int


@lru_cache
def _dummy_password_hash() -> str:
    """A real Argon2 hash used to equalize timing when no account matches."""
    return hash_password(generate_opaque_token())


class AuthService:
    """Owns the transaction boundary for each authentication use case."""

    def __init__(self, session: Session, settings: Settings, dispatcher: EmailDispatcher) -> None:
        self._session = session
        self._settings = settings
        self._dispatcher = dispatcher

    def register(self, email: str, password: str) -> User:
        """Create an unverified account with the default role and queue its verification email.

        The account, its role, and its verification token commit together or not at all.
        """
        normalized_email = normalize_email(email)
        if user_repository.get_user_by_email(self._session, normalized_email) is not None:
            raise EmailAlreadyRegisteredError()

        try:
            user = user_repository.add_user(
                self._session,
                email=normalized_email,
                hashed_password=hash_password(password),
            )
            RbacService(self._session).assign_default_role(user.id)
            token, raw_token = self._issue_verification_token(user)
            self._session.commit()
        except IntegrityError as error:
            # A concurrent registration won the unique constraint.
            self._session.rollback()
            raise EmailAlreadyRegisteredError() from error
        except DefaultRoleMissingError:
            self._session.rollback()
            raise

        logger.info("User %s registered", user.id)
        try:
            self._dispatcher.queue_verification_email(token.id, raw_token)
        except EmailDispatchError as error:
            # The account stays committed; the user can request another email.
            raise VerificationEmailUnavailableError() from error
        return user

    def verify_email(self, raw_token: str) -> None:
        """Consume a verification token and mark its user as verified."""
        token = self._consume_action_token(raw_token, ActionTokenPurpose.EMAIL_VERIFICATION)
        token.user.is_verified = True
        self._session.commit()
        logger.info("User %s verified their email address", token.user_id)

    def forgot_password(self, email: str) -> None:
        """Queue a password-reset email for an active account.

        The caller always receives the same neutral response, so unknown or
        disabled accounts and dispatch failures are handled silently here.
        """
        user = user_repository.get_user_by_email(self._session, normalize_email(email))
        if user is None or not user.is_active:
            return

        token_repository.delete_unused_action_tokens(
            self._session,
            user_id=user.id,
            purpose=ActionTokenPurpose.PASSWORD_RESET,
        )
        raw_token = generate_opaque_token()
        lifetime = timedelta(minutes=self._settings.password_reset_token_ttl_minutes)
        token = token_repository.add_action_token(
            self._session,
            user_id=user.id,
            purpose=ActionTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(raw_token),
            expires_at=datetime.now(UTC) + lifetime,
        )
        self._session.commit()

        try:
            self._dispatcher.queue_password_reset_email(token.id, raw_token)
        except EmailDispatchError:
            logger.error("Password-reset email for user %s could not be queued", user.id)

    def reset_password(self, raw_token: str, new_password: str) -> None:
        """Consume a reset token, replace the password, and end every session."""
        token = self._consume_action_token(raw_token, ActionTokenPurpose.PASSWORD_RESET)
        user = token.user
        user.hashed_password = hash_password(new_password)
        if not user.is_verified:
            # Using the emailed link proves control of the address.
            user.is_verified = True
            token_repository.delete_unused_action_tokens(
                self._session,
                user_id=user.id,
                purpose=ActionTokenPurpose.EMAIL_VERIFICATION,
            )
        token_repository.revoke_user_refresh_tokens(self._session, user.id, datetime.now(UTC))
        self._session.commit()
        logger.info("User %s reset their password; all sessions revoked", user.id)

    def _consume_action_token(self, raw_token: str, purpose: ActionTokenPurpose) -> ActionToken:
        """Lock, validate, and mark a single-use action token as used.

        Other unused tokens of the same purpose are invalidated. The caller
        commits. Every failure raises the same ``InvalidActionTokenError``.
        """
        now = datetime.now(UTC)
        token = token_repository.get_action_token_by_hash_for_update(
            self._session, hash_opaque_token(raw_token)
        )
        if (
            token is None
            or token.purpose is not purpose
            or token.used_at is not None
            or token.expires_at <= now
            or not token.user.is_active
        ):
            raise InvalidActionTokenError()

        token.used_at = now
        token_repository.delete_unused_action_tokens(
            self._session,
            user_id=token.user_id,
            purpose=purpose,
            keep_token_id=token.id,
        )
        return token

    def resend_verification(self, email: str) -> None:
        """Replace outstanding verification tokens for an eligible account.

        The caller always receives the same neutral response, so ineligible
        accounts and dispatch failures are handled silently here.
        """
        user = user_repository.get_user_by_email(self._session, normalize_email(email))
        if user is None or not user.is_active or user.is_verified:
            return

        token_repository.delete_unused_action_tokens(
            self._session,
            user_id=user.id,
            purpose=ActionTokenPurpose.EMAIL_VERIFICATION,
        )
        token, raw_token = self._issue_verification_token(user)
        self._session.commit()

        try:
            self._dispatcher.queue_verification_email(token.id, raw_token)
        except EmailDispatchError:
            logger.error("Verification email for user %s could not be queued", user.id)

    def login(self, email: str, password: str) -> IssuedTokens:
        """Authenticate credentials and start a new refresh-token family."""
        user = user_repository.get_user_by_email(self._session, normalize_email(email))
        if user is None:
            verify_password(password, _dummy_password_hash())
            raise InvalidCredentialsError()
        if not verify_password(password, user.hashed_password):
            raise InvalidCredentialsError()

        # Account state is disclosed only to a client that knows the password.
        if not user.is_active:
            raise AccountDisabledError()
        if not user.is_verified:
            raise EmailNotVerifiedError()

        _, tokens = self._issue_tokens(user, family_id=uuid4())
        self._session.commit()
        logger.info("User %s logged in", user.id)
        return tokens

    def refresh(self, raw_refresh_token: str | None) -> IssuedTokens:
        """Rotate a refresh token within its family and issue a new access token.

        Presenting a token that was already rotated or revoked is treated as
        theft: the whole family is revoked, ending every session derived from it.
        """
        if not raw_refresh_token:
            raise InvalidRefreshTokenError()

        now = datetime.now(UTC)
        current = token_repository.get_refresh_token_by_hash_for_update(
            self._session, hash_opaque_token(raw_refresh_token)
        )
        if current is None:
            raise InvalidRefreshTokenError()

        if current.used_at is not None or current.revoked_at is not None:
            token_repository.revoke_refresh_token_family(self._session, current.family_id, now)
            self._session.commit()
            logger.warning(
                "Refresh token reuse detected; revoked family %s of user %s",
                current.family_id,
                current.user_id,
            )
            raise InvalidRefreshTokenError()

        if current.expires_at <= now or not current.user.is_active or not current.user.is_verified:
            raise InvalidRefreshTokenError()

        replacement, tokens = self._issue_tokens(current.user, family_id=current.family_id)
        current.used_at = now
        current.replaced_by_id = replacement.id
        self._session.commit()
        logger.info("Refresh token rotated in family %s", current.family_id)
        return tokens

    def logout(self, raw_refresh_token: str | None) -> None:
        """Revoke the presented token's family. Unknown or missing tokens are ignored."""
        if not raw_refresh_token:
            return

        token = token_repository.get_refresh_token_by_hash(
            self._session, hash_opaque_token(raw_refresh_token)
        )
        if token is None:
            return

        token_repository.revoke_refresh_token_family(
            self._session, token.family_id, datetime.now(UTC)
        )
        self._session.commit()
        logger.info("User %s logged out; revoked family %s", token.user_id, token.family_id)

    def authenticate_access_token(self, token: str) -> User:
        """Resolve a bearer token to an active, verified user."""
        try:
            claims = decode_access_token(token, settings=self._settings)
        except InvalidAccessTokenError as error:
            raise AccessTokenRejectedError() from error

        user = user_repository.get_user_by_id(self._session, claims.sub)
        if user is None or not user.is_active or not user.is_verified:
            raise AccessTokenRejectedError()
        return user

    def _issue_tokens(self, user: User, *, family_id: UUID) -> tuple[RefreshToken, IssuedTokens]:
        """Stage a new refresh token in ``family_id`` and sign an access token."""
        refresh_lifetime = timedelta(days=self._settings.refresh_token_ttl_days)
        raw_refresh_token = generate_opaque_token()
        refresh_token = token_repository.add_refresh_token(
            self._session,
            user_id=user.id,
            family_id=family_id,
            token_hash=hash_opaque_token(raw_refresh_token),
            expires_at=datetime.now(UTC) + refresh_lifetime,
        )
        tokens = IssuedTokens(
            access_token=create_access_token(user.id, settings=self._settings),
            access_token_expires_in=self._settings.access_token_ttl_minutes * 60,
            refresh_token=raw_refresh_token,
            refresh_token_max_age=int(refresh_lifetime.total_seconds()),
        )
        return refresh_token, tokens

    def _issue_verification_token(self, user: User) -> tuple[ActionToken, str]:
        raw_token = generate_opaque_token()
        lifetime = timedelta(hours=self._settings.email_verification_token_ttl_hours)
        token = token_repository.add_action_token(
            self._session,
            user_id=user.id,
            purpose=ActionTokenPurpose.EMAIL_VERIFICATION,
            token_hash=hash_opaque_token(raw_token),
            expires_at=datetime.now(UTC) + lifetime,
        )
        return token, raw_token


def get_auth_service(
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: Annotated[EmailDispatcher, Depends(get_email_dispatcher)],
) -> AuthService:
    return AuthService(session, settings, dispatcher)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
