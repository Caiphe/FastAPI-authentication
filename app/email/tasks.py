"""Celery tasks and dispatch helpers for authentication emails.

Tasks receive a purpose-built payload of the action-token id and the raw token.
The raw token cannot be recovered from its stored hash, so it must travel in the
message; it is redacted from every log-facing representation of the task.
"""

import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from celery import Task
from kombu.exceptions import OperationalError as BrokerError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy.exc import OperationalError as DatabaseUnavailableError
from sqlalchemy.orm import Session

from app.auth.models import ActionTokenPurpose
from app.auth.repository import get_action_token
from app.core.config import Settings, get_settings
from app.core.database import SessionFactory
from app.core.security import verify_opaque_token
from app.email.ledger import DeliveryLedger, get_delivery_ledger
from app.email.provider import EmailDeliveryError, EmailProvider, get_email_provider
from app.email.templates import render_action_email
from app.worker import celery_app

logger = logging.getLogger(__name__)

# Transient failures of the provider, Redis, or PostgreSQL are retried with backoff.
RETRYABLE_ERRORS = (
    EmailDeliveryError,
    RedisConnectionError,
    RedisTimeoutError,
    DatabaseUnavailableError,
)
TASK_OPTIONS: dict[str, Any] = {
    "autoretry_for": RETRYABLE_ERRORS,
    "retry_backoff": True,
    "retry_backoff_max": 300,
    "retry_jitter": True,
    "max_retries": get_settings().email_task_max_retries,
}


class DeliveryOutcome(StrEnum):
    """Result of a single email task execution."""

    SENT = "sent"
    DUPLICATE = "duplicate"
    SKIPPED = "skipped"


class EmailDispatchError(RuntimeError):
    """Raised when an email task cannot be handed to the broker."""


def deliver_action_email(
    session: Session,
    *,
    action_token_id: UUID,
    token: str,
    purpose: ActionTokenPurpose,
    provider: EmailProvider,
    ledger: DeliveryLedger,
    settings: Settings,
    now: datetime | None = None,
) -> DeliveryOutcome:
    """Send an action-token email once, and only while the token is still usable."""
    current_time = now or datetime.now(UTC)
    record = get_action_token(session, action_token_id)

    if (
        record is None
        or record.purpose is not purpose
        or not verify_opaque_token(token, record.token_hash)
    ):
        logger.warning("Email skipped: action token %s not found or mismatched", action_token_id)
        return DeliveryOutcome.SKIPPED

    user = record.user
    if record.used_at is not None or record.expires_at <= current_time or not user.is_active:
        logger.info("Email skipped: action token %s is no longer usable", action_token_id)
        return DeliveryOutcome.SKIPPED

    if purpose is ActionTokenPurpose.EMAIL_VERIFICATION and user.is_verified:
        logger.info("Email skipped: user for action token %s is already verified", action_token_id)
        return DeliveryOutcome.SKIPPED

    ledger_key = str(action_token_id)
    if not ledger.claim(ledger_key):
        logger.info("Email skipped: action token %s is already sent or sending", action_token_id)
        return DeliveryOutcome.DUPLICATE

    message = render_action_email(settings, purpose=purpose, recipient=user.email, token=token)
    try:
        provider.send(message)
    except BaseException:
        ledger.release(ledger_key)
        raise
    remaining_seconds = int((record.expires_at - current_time).total_seconds())
    ledger.mark_delivered(ledger_key, ttl_seconds=remaining_seconds)
    logger.info("Email sent for action token %s (%s)", action_token_id, purpose.value)
    return DeliveryOutcome.SENT


def _run_delivery(action_token_id: str, token: str, purpose: ActionTokenPurpose) -> str:
    settings = get_settings()
    with SessionFactory() as session:
        outcome = deliver_action_email(
            session,
            action_token_id=UUID(action_token_id),
            token=token,
            purpose=purpose,
            provider=get_email_provider(settings),
            ledger=get_delivery_ledger(),
            settings=settings,
        )
    return outcome.value


@celery_app.task(name="auth.email.send_verification_email", **TASK_OPTIONS)
def send_verification_email(action_token_id: str, token: str) -> str:
    """Deliver an email-verification link."""
    return _run_delivery(action_token_id, token, ActionTokenPurpose.EMAIL_VERIFICATION)


@celery_app.task(name="auth.email.send_password_reset_email", **TASK_OPTIONS)
def send_password_reset_email(action_token_id: str, token: str) -> str:
    """Deliver a password-reset link."""
    return _run_delivery(action_token_id, token, ActionTokenPurpose.PASSWORD_RESET)


def queue_verification_email(action_token_id: UUID, token: str) -> None:
    """Queue a verification email. Call only after the token has been committed."""
    _dispatch(send_verification_email, action_token_id, token)


def queue_password_reset_email(action_token_id: UUID, token: str) -> None:
    """Queue a password-reset email. Call only after the token has been committed."""
    _dispatch(send_password_reset_email, action_token_id, token)


def _dispatch(task: Task[..., Any], action_token_id: UUID, token: str) -> None:
    token_id = str(action_token_id)
    try:
        task.apply_async(
            kwargs={"action_token_id": token_id, "token": token},
            # Celery shows kwargsrepr in logs and events; celery-types omits the option.
            kwargsrepr=repr({"action_token_id": token_id, "token": "[REDACTED]"}),  # type: ignore[call-arg]
        )
    except (BrokerError, RedisConnectionError, RedisTimeoutError) as error:
        logger.error("Email dispatch failed for action token %s: broker unavailable", token_id)
        raise EmailDispatchError("email task could not be queued") from error
