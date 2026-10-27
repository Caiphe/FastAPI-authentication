"""Email provider, template, and dispatch tests that need no external services."""

import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from kombu.exceptions import OperationalError as BrokerError
from sqlalchemy.exc import OperationalError as DatabaseUnavailableError

from app.auth.models import ActionTokenPurpose
from app.core.config import Environment, Settings, get_settings
from app.email import tasks
from app.email.provider import (
    DevelopmentEmailProvider,
    EmailDeliveryError,
    EmailMessage,
    get_email_provider,
    mask_email,
)
from app.email.templates import build_action_url, render_action_email

RAW_TOKEN = "raw-action-token-value-that-must-stay-secret"


def email_settings(**overrides: Any) -> Settings:
    return Settings.model_validate({"environment": Environment.TEST, **overrides})


def sample_message() -> EmailMessage:
    return EmailMessage(
        recipient="jane@example.com",
        subject="Verify your email address",
        text_body=f"link #token={RAW_TOKEN}",
        html_body=f"<a href='#token={RAW_TOKEN}'>link</a>",
    )


def test_mask_email_keeps_only_a_hint() -> None:
    assert mask_email("jane@example.com") == "j***@example.com"
    assert mask_email("not-an-address") == "***"


def test_development_provider_logs_only_safe_metadata(caplog: pytest.LogCaptureFixture) -> None:
    provider = DevelopmentEmailProvider(sender="no-reply@localhost")

    with caplog.at_level(logging.DEBUG):
        provider.send(sample_message())

    assert "j***@example.com" in caplog.text
    assert "Verify your email address" in caplog.text
    assert "jane@example.com" not in caplog.text
    assert RAW_TOKEN not in caplog.text


def test_development_provider_records_full_message_in_outbox(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    outbox = tmp_path / "outbox"
    provider = DevelopmentEmailProvider(sender="no-reply@localhost", outbox_dir=outbox)

    with caplog.at_level(logging.DEBUG):
        provider.send(sample_message())

    [recorded] = list(outbox.glob("*.eml"))
    contents = recorded.read_text()
    assert "To: jane@example.com" in contents
    assert f"#token={RAW_TOKEN}" in contents
    assert RAW_TOKEN not in caplog.text


def test_development_provider_reports_outbox_failure_as_retryable(tmp_path: Path) -> None:
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("")
    provider = DevelopmentEmailProvider(sender="no-reply@localhost", outbox_dir=blocked)

    with pytest.raises(EmailDeliveryError):
        provider.send(sample_message())


def test_provider_factory_uses_configuration(tmp_path: Path) -> None:
    provider = get_email_provider(email_settings(email_outbox_dir=tmp_path))

    assert isinstance(provider, DevelopmentEmailProvider)


@pytest.mark.parametrize(
    ("purpose", "path"),
    [
        (ActionTokenPurpose.EMAIL_VERIFICATION, "/verify-email"),
        (ActionTokenPurpose.PASSWORD_RESET, "/reset-password"),
    ],
)
def test_action_url_carries_token_in_fragment(purpose: ActionTokenPurpose, path: str) -> None:
    settings = email_settings(frontend_base_url="https://app.example.com/")

    url = build_action_url(settings, purpose, "abc-_123")

    assert url == f"https://app.example.com{path}#token=abc-_123"


def test_verification_email_renders_link_and_lifetime() -> None:
    message = render_action_email(
        email_settings(),
        purpose=ActionTokenPurpose.EMAIL_VERIFICATION,
        recipient="jane@example.com",
        token=RAW_TOKEN,
    )

    assert message.recipient == "jane@example.com"
    assert message.subject == "Verify your email address"
    assert f"http://localhost:3000/verify-email#token={RAW_TOKEN}" in message.text_body
    assert f'href="http://localhost:3000/verify-email#token={RAW_TOKEN}"' in message.html_body
    assert "expires in 1 day." in message.text_body


def test_password_reset_email_renders_link_and_lifetime() -> None:
    message = render_action_email(
        email_settings(),
        purpose=ActionTokenPurpose.PASSWORD_RESET,
        recipient="jane@example.com",
        token=RAW_TOKEN,
    )

    assert message.subject == "Reset your password"
    assert f"http://localhost:3000/reset-password#token={RAW_TOKEN}" in message.text_body
    assert "1 hour." in message.text_body


def test_html_templates_escape_context() -> None:
    message = render_action_email(
        email_settings(app_name="<script>alert(1)</script>"),
        purpose=ActionTokenPurpose.PASSWORD_RESET,
        recipient="jane@example.com",
        token=RAW_TOKEN,
    )

    assert "<script>" not in message.html_body
    assert "&lt;script&gt;" in message.html_body


@pytest.mark.parametrize(
    ("queue", "task"),
    [
        (tasks.queue_verification_email, tasks.send_verification_email),
        (tasks.queue_password_reset_email, tasks.send_password_reset_email),
    ],
)
def test_dispatch_redacts_token_from_task_representation(
    monkeypatch: pytest.MonkeyPatch, queue: Any, task: Any
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(task, "apply_async", lambda **options: calls.append(options))
    token_id = uuid4()

    queue(token_id, RAW_TOKEN)

    [options] = calls
    assert options["kwargs"] == {"action_token_id": str(token_id), "token": RAW_TOKEN}
    assert RAW_TOKEN not in options["kwargsrepr"]
    assert "[REDACTED]" in options["kwargsrepr"]


def test_dispatch_failure_raises_service_error_without_logging_token(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def unavailable(**options: Any) -> None:
        raise BrokerError("connection refused")

    monkeypatch.setattr(tasks.send_verification_email, "apply_async", unavailable)

    with caplog.at_level(logging.DEBUG), pytest.raises(tasks.EmailDispatchError):
        tasks.queue_verification_email(uuid4(), RAW_TOKEN)

    assert "broker unavailable" in caplog.text
    assert RAW_TOKEN not in caplog.text


def test_email_tasks_have_bounded_retry_policy() -> None:
    for task in (tasks.send_verification_email, tasks.send_password_reset_email):
        assert EmailDeliveryError in task.autoretry_for
        # A database outage must delay delivery, not lose the email.
        assert DatabaseUnavailableError in task.autoretry_for
        assert task.max_retries == get_settings().email_task_max_retries
        assert task.retry_backoff is True
        assert task.retry_jitter is True
