"""Email task behavior against PostgreSQL, with provider and ledger replaced."""

import logging
from collections.abc import Iterator
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.auth.models import ActionToken, ActionTokenPurpose
from app.core.config import Environment, Settings
from app.core.security import generate_opaque_token, hash_opaque_token
from app.email import tasks
from app.email.provider import EmailDeliveryError, EmailMessage
from app.users.models import User
from app.worker import celery_app

pytestmark = pytest.mark.integration


class RecordingProvider:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.attempts = 0
        self.sent: list[EmailMessage] = []

    def send(self, message: EmailMessage) -> None:
        self.attempts += 1
        if self.attempts <= self.failures:
            raise EmailDeliveryError("temporary provider outage")
        self.sent.append(message)


class MemoryLedger:
    def __init__(self) -> None:
        self.claims: set[str] = set()
        self.markers: dict[str, int] = {}

    def claim(self, key: str) -> bool:
        if key in self.claims:
            return False
        self.claims.add(key)
        return True

    def release(self, key: str) -> None:
        self.claims.discard(key)

    def mark_delivered(self, key: str, ttl_seconds: int) -> None:
        self.markers[key] = ttl_seconds


@pytest.fixture
def settings() -> Settings:
    return Settings.model_validate({"environment": Environment.TEST})


@pytest.fixture
def provider() -> RecordingProvider:
    return RecordingProvider()


@pytest.fixture
def ledger() -> MemoryLedger:
    return MemoryLedger()


@pytest.fixture
def worker_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    db_session: Session,
    settings: Settings,
    provider: RecordingProvider,
    ledger: MemoryLedger,
) -> Iterator[None]:
    """Route the real task bodies to the test session, provider, and ledger."""
    monkeypatch.setattr(tasks, "SessionFactory", lambda: nullcontext(db_session))
    monkeypatch.setattr(tasks, "get_settings", lambda: settings)
    monkeypatch.setattr(tasks, "get_email_provider", lambda _settings: provider)
    monkeypatch.setattr(tasks, "get_delivery_ledger", lambda: ledger)
    monkeypatch.setattr(celery_app.conf, "task_always_eager", True)
    yield


def create_action_token(
    session: Session,
    purpose: ActionTokenPurpose,
    *,
    expires_in: timedelta = timedelta(hours=1),
    used: bool = False,
    is_verified: bool = False,
    is_active: bool = True,
) -> tuple[ActionToken, str]:
    user = User(
        email=f"user-{uuid4().hex}@example.com",
        hashed_password="not-a-real-hash",
        is_verified=is_verified,
        is_active=is_active,
    )
    raw_token = generate_opaque_token()
    now = datetime.now(UTC)
    record = ActionToken(
        user=user,
        purpose=purpose,
        token_hash=hash_opaque_token(raw_token),
        expires_at=now + expires_in,
        used_at=now if used else None,
    )
    session.add(record)
    session.flush()
    return record, raw_token


def deliver(
    session: Session,
    settings: Settings,
    provider: RecordingProvider,
    ledger: MemoryLedger,
    record: ActionToken,
    token: str,
    purpose: ActionTokenPurpose | None = None,
) -> tasks.DeliveryOutcome:
    return tasks.deliver_action_email(
        session,
        action_token_id=record.id,
        token=token,
        purpose=purpose or record.purpose,
        provider=provider,
        ledger=ledger,
        settings=settings,
    )


@pytest.mark.parametrize("purpose", list(ActionTokenPurpose))
def test_delivery_sends_once_and_is_idempotent(
    db_session: Session,
    settings: Settings,
    provider: RecordingProvider,
    ledger: MemoryLedger,
    purpose: ActionTokenPurpose,
) -> None:
    record, token = create_action_token(db_session, purpose)

    first = deliver(db_session, settings, provider, ledger, record, token)
    second = deliver(db_session, settings, provider, ledger, record, token)

    assert first is tasks.DeliveryOutcome.SENT
    assert second is tasks.DeliveryOutcome.DUPLICATE
    [message] = provider.sent
    assert message.recipient == record.user.email
    assert f"#token={token}" in message.text_body
    assert 3500 < ledger.markers[str(record.id)] <= 3600


@pytest.mark.parametrize(
    ("options", "purpose_override"),
    [
        ({"expires_in": timedelta(seconds=-1)}, None),
        ({"used": True}, None),
        ({"is_active": False}, None),
        ({"is_verified": True}, None),
        ({}, ActionTokenPurpose.PASSWORD_RESET),
    ],
    ids=["expired", "used", "inactive-user", "already-verified", "wrong-purpose"],
)
def test_delivery_skips_tokens_that_are_no_longer_usable(
    db_session: Session,
    settings: Settings,
    provider: RecordingProvider,
    ledger: MemoryLedger,
    options: dict[str, object],
    purpose_override: ActionTokenPurpose | None,
) -> None:
    record, token = create_action_token(
        db_session,
        ActionTokenPurpose.EMAIL_VERIFICATION,
        **options,  # type: ignore[arg-type]
    )

    outcome = deliver(db_session, settings, provider, ledger, record, token, purpose_override)

    assert outcome is tasks.DeliveryOutcome.SKIPPED
    assert provider.sent == []
    assert ledger.markers == {}


def test_delivery_rejects_token_that_does_not_match_hash(
    db_session: Session, settings: Settings, provider: RecordingProvider, ledger: MemoryLedger
) -> None:
    record, _ = create_action_token(db_session, ActionTokenPurpose.PASSWORD_RESET)

    outcome = deliver(db_session, settings, provider, ledger, record, generate_opaque_token())

    assert outcome is tasks.DeliveryOutcome.SKIPPED
    assert provider.sent == []


def test_failed_send_is_not_marked_delivered(
    db_session: Session, settings: Settings, ledger: MemoryLedger
) -> None:
    record, token = create_action_token(db_session, ActionTokenPurpose.PASSWORD_RESET)

    with pytest.raises(EmailDeliveryError):
        deliver(db_session, settings, RecordingProvider(failures=1), ledger, record, token)

    assert ledger.markers == {}
    assert ledger.claims == set()


@pytest.mark.usefixtures("worker_dependencies")
def test_queued_task_runs_eagerly_without_worker_and_never_logs_token(
    db_session: Session,
    provider: RecordingProvider,
    caplog: pytest.LogCaptureFixture,
) -> None:
    record, token = create_action_token(db_session, ActionTokenPurpose.EMAIL_VERIFICATION)

    with caplog.at_level(logging.DEBUG):
        tasks.queue_verification_email(record.id, token)
        tasks.queue_verification_email(record.id, token)

    assert len(provider.sent) == 1
    assert caplog.text
    assert token not in caplog.text
    assert hash_opaque_token(token) not in caplog.text


@pytest.mark.usefixtures("worker_dependencies")
def test_task_retries_transient_provider_failures(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    ledger: MemoryLedger,
) -> None:
    flaky = RecordingProvider(failures=2)
    monkeypatch.setattr(tasks, "get_email_provider", lambda _settings: flaky)
    record, token = create_action_token(db_session, ActionTokenPurpose.PASSWORD_RESET)

    result = tasks.send_password_reset_email.apply(
        kwargs={"action_token_id": str(record.id), "token": token}
    )

    assert result.get() == tasks.DeliveryOutcome.SENT
    assert flaky.attempts == 3
    assert len(flaky.sent) == 1
    assert str(record.id) in ledger.markers


@pytest.mark.usefixtures("worker_dependencies")
def test_task_gives_up_after_bounded_retries(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    ledger: MemoryLedger,
) -> None:
    broken = RecordingProvider(failures=100)
    monkeypatch.setattr(tasks, "get_email_provider", lambda _settings: broken)
    monkeypatch.setattr(tasks.send_verification_email, "max_retries", 2)
    record, token = create_action_token(db_session, ActionTokenPurpose.EMAIL_VERIFICATION)

    result = tasks.send_verification_email.apply(
        kwargs={"action_token_id": str(record.id), "token": token}
    )

    with pytest.raises(EmailDeliveryError):
        result.get()
    assert broken.attempts == 3
    assert ledger.markers == {}
