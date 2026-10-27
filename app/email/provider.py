"""Vendor-neutral email delivery interface and the development adapter."""

import logging
from dataclasses import dataclass
from email.message import EmailMessage as MimeMessage
from email.utils import make_msgid
from pathlib import Path
from typing import Protocol

from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """A fully rendered message ready for delivery."""

    recipient: str
    subject: str
    text_body: str
    html_body: str


class EmailDeliveryError(Exception):
    """Raised by providers for transient failures that are safe to retry."""


class EmailProvider(Protocol):
    """Delivers rendered messages. Implementations must not log message bodies."""

    def send(self, message: EmailMessage) -> None: ...


class DevelopmentEmailProvider:
    """Record messages locally instead of delivering them.

    Only safe metadata is logged. When an outbox directory is configured, the
    complete message (including its link) is written there as an ``.eml`` file so
    developers can complete flows locally without tokens ever reaching the logs.
    """

    def __init__(self, sender: str, outbox_dir: Path | None = None) -> None:
        self._sender = sender
        self._outbox_dir = outbox_dir

    def send(self, message: EmailMessage) -> None:
        message_id = make_msgid(domain="auth.local")
        if self._outbox_dir is not None:
            self._write_to_outbox(self._outbox_dir, message, message_id)

        logger.info(
            "Development email recorded: message_id=%s recipient=%s subject=%r outbox=%s",
            message_id,
            mask_email(message.recipient),
            message.subject,
            self._outbox_dir is not None,
        )

    def _write_to_outbox(self, outbox_dir: Path, message: EmailMessage, message_id: str) -> None:
        mime = MimeMessage()
        mime["Message-ID"] = message_id
        mime["From"] = self._sender
        mime["To"] = message.recipient
        mime["Subject"] = message.subject
        # 8bit keeps links copyable; quoted-printable would wrap and escape them.
        mime.set_content(message.text_body, cte="8bit")
        mime.add_alternative(message.html_body, subtype="html", cte="8bit")

        try:
            outbox_dir.mkdir(parents=True, exist_ok=True)
            filename = message_id.strip("<>").replace("@", "_") + ".eml"
            (outbox_dir / filename).write_bytes(mime.as_bytes())
        except OSError as error:
            raise EmailDeliveryError("could not write message to the development outbox") from error


def get_email_provider(settings: Settings | None = None) -> EmailProvider:
    """Return the provider selected by configuration."""
    resolved_settings = settings or get_settings()
    return DevelopmentEmailProvider(
        sender=resolved_settings.email_from_address,
        outbox_dir=resolved_settings.email_outbox_dir,
    )


def mask_email(address: str) -> str:
    """Reduce an address to a log-safe hint such as ``j***@example.com``."""
    local, separator, domain = address.partition("@")
    if not separator:
        return "***"
    return f"{local[:1]}***@{domain}"
