"""Logging setup with a process-wide safety net that redacts credentials.

Application code must still never log secrets. Redaction exists to catch
mistakes, including in third-party log messages.
"""

import logging
import re
from typing import Any

from app.core.config import Settings

REDACTED = "[REDACTED]"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Signed JWTs, wherever they appear.
    (re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*"), REDACTED),
    (re.compile(r"(?i)\b(bearer)\s+[\w.~+/=-]+"), rf"\1 {REDACTED}"),
    # key=value or "key": "value" for credential-bearing names, including cookies.
    (
        re.compile(
            r"(?i)\b((?:new_)?password|(?:refresh_|access_)?token|secret(?:_key)?|authorization|cookie)"
            r"""(["']?\s*[:=]\s*["']?)[^\s"'&;,)}]+"""
        ),
        rf"\1\2{REDACTED}",
    ),
    # Passwords embedded in connection URLs.
    (re.compile(r"(\w+://[^:/@\s]+:)[^@\s]+@"), rf"\1{REDACTED}@"),
)

_installed = False


def redact(message: str) -> str:
    """Replace credential-like substrings in a log message."""
    for pattern, replacement in _PATTERNS:
        message = pattern.sub(replacement, message)
    return message


def install_redaction() -> None:
    """Redact every log record at creation time, for all loggers. Idempotent."""
    global _installed
    if _installed:
        return
    previous_factory = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous_factory(*args, **kwargs)
        try:
            message = record.getMessage()
        except Exception:
            return record
        redacted = redact(message)
        if redacted != message:
            record.msg, record.args = redacted, None
        return record

    logging.setLogRecordFactory(factory)
    _installed = True


def configure_logging(settings: Settings) -> None:
    """Install redaction and make application logs visible at the configured level."""
    install_redaction()
    logging.getLogger("app").setLevel(settings.log_level)
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(handler)
        root.setLevel(logging.WARNING)
