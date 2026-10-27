"""Email dispatch boundary used by authentication services.

Services depend on this protocol rather than on Celery, so tests can replace
dispatch without a broker or worker.
"""

from typing import Protocol
from uuid import UUID

from app.email import tasks


class EmailDispatcher(Protocol):
    """Queues action-token emails. Raises ``EmailDispatchError`` on broker failure."""

    def queue_verification_email(self, action_token_id: UUID, token: str) -> None: ...

    def queue_password_reset_email(self, action_token_id: UUID, token: str) -> None: ...


class CeleryEmailDispatcher:
    """Dispatch emails as Celery tasks."""

    def queue_verification_email(self, action_token_id: UUID, token: str) -> None:
        tasks.queue_verification_email(action_token_id, token)

    def queue_password_reset_email(self, action_token_id: UUID, token: str) -> None:
        tasks.queue_password_reset_email(action_token_id, token)


def get_email_dispatcher() -> EmailDispatcher:
    """FastAPI dependency returning the configured dispatcher."""
    return CeleryEmailDispatcher()
