"""Rendering of authentication emails from packaged templates."""

from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from app.auth.models import ActionTokenPurpose
from app.core.config import Settings
from app.email.provider import EmailMessage

TEMPLATE_DIR = Path(__file__).parent / "templates"

SUBJECTS = {
    ActionTokenPurpose.EMAIL_VERIFICATION: "Verify your email address",
    ActionTokenPurpose.PASSWORD_RESET: "Reset your password",
}

template_environment = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(enabled_extensions=("html",), default_for_string=False),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)


def build_action_url(settings: Settings, purpose: ActionTokenPurpose, token: str) -> str:
    """Build the frontend link for an action token.

    The token is placed in the URL fragment so it is not sent to the frontend
    host's access logs or leaked through ``Referer`` headers.
    """
    path = (
        settings.frontend_verify_email_path
        if purpose is ActionTokenPurpose.EMAIL_VERIFICATION
        else settings.frontend_reset_password_path
    )
    base_url = str(settings.frontend_base_url).rstrip("/")
    return f"{base_url}{path}#{urlencode({'token': token})}"


def token_lifetime(settings: Settings, purpose: ActionTokenPurpose) -> timedelta:
    """Return the configured lifetime for an action token purpose."""
    if purpose is ActionTokenPurpose.EMAIL_VERIFICATION:
        return timedelta(hours=settings.email_verification_token_ttl_hours)
    return timedelta(minutes=settings.password_reset_token_ttl_minutes)


def render_action_email(
    settings: Settings,
    *,
    purpose: ActionTokenPurpose,
    recipient: str,
    token: str,
) -> EmailMessage:
    """Render the text and HTML bodies for an action-token email."""
    context = {
        "app_name": settings.app_name,
        "action_url": build_action_url(settings, purpose, token),
        "expires_in": describe_duration(token_lifetime(settings, purpose)),
    }
    return EmailMessage(
        recipient=recipient,
        subject=SUBJECTS[purpose],
        text_body=template_environment.get_template(f"{purpose.value}.txt").render(context),
        html_body=template_environment.get_template(f"{purpose.value}.html").render(context),
    )


def describe_duration(duration: timedelta) -> str:
    """Describe a whole-minute duration in the largest exact unit."""
    minutes = int(duration.total_seconds()) // 60
    for unit, size in (("day", 1440), ("hour", 60), ("minute", 1)):
        if minutes % size == 0:
            count = minutes // size
            return f"{count} {unit}{'' if count == 1 else 's'}"
    return f"{minutes} minutes"
