"""Shared test fixtures."""

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, inspect
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.auth.dispatch import get_email_dispatcher
from app.core import database
from app.core.config import Environment, Settings
from app.email.tasks import EmailDispatchError
from app.main import create_app
from app.users.models import User


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep settings built in tests independent of the developer's .env and AUTH_* vars.

    The shared database engine is created at import time from the real
    configuration, so integration tests still reach the local services.
    """
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    for name in list(os.environ):
        if name.startswith("AUTH_"):
            monkeypatch.delenv(name)


@pytest.fixture
def db_session() -> Iterator[Session]:
    """Yield a PostgreSQL session whose work is rolled back after the test.

    Requires ``docker compose up -d --wait`` and ``alembic upgrade head``.
    """
    try:
        connection = database.engine.connect()
    except OperationalError as error:
        reason = str(error.orig).splitlines()[-1].strip()
        pytest.skip(f"PostgreSQL is unavailable for integration tests: {reason}")

    schema_ready = inspect(connection).has_table("action_tokens")
    connection.rollback()
    if not schema_ready:
        connection.close()
        pytest.fail("Database schema is missing; run `python -m alembic upgrade head`")

    transaction = connection.begin()
    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
        # Match SessionFactory so tests see the same flush behaviour as production.
        autoflush=False,
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@dataclass
class QueuedEmail:
    purpose: str
    action_token_id: UUID
    token: str
    transaction_open: bool


@dataclass
class FakeDispatcher:
    """Records queued emails; can simulate a broker outage."""

    session: Session | None = None
    fail: bool = False
    queued: list[QueuedEmail] = field(default_factory=list)

    def queue_verification_email(self, action_token_id: UUID, token: str) -> None:
        self._queue("email_verification", action_token_id, token)

    def queue_password_reset_email(self, action_token_id: UUID, token: str) -> None:
        self._queue("password_reset", action_token_id, token)

    def _queue(self, purpose: str, action_token_id: UUID, token: str) -> None:
        if self.fail:
            raise EmailDispatchError("broker unavailable")
        transaction_open = self.session is not None and self.session.in_transaction()
        self.queued.append(QueuedEmail(purpose, action_token_id, token, transaction_open))


@pytest.fixture
def settings() -> Settings:
    return Settings.model_validate(
        {"environment": Environment.TEST, "secret_key": "test-signing-key-" + "x" * 32}
    )


@pytest.fixture
def dispatcher() -> FakeDispatcher:
    return FakeDispatcher()


@pytest.fixture
def make_app(settings: Settings, dispatcher: FakeDispatcher) -> Callable[..., FastAPI]:
    """Build an app whose email dispatch is replaced and optionally bound to a session."""

    def build(session: Session | None = None) -> FastAPI:
        application = create_app(settings)
        application.dependency_overrides[get_email_dispatcher] = lambda: dispatcher
        if session is not None:
            dispatcher.session = session
            application.dependency_overrides[database.get_db_session] = lambda: session
        return application

    return build


@pytest.fixture
def client(make_app: Callable[..., FastAPI], db_session: Session) -> Iterator[TestClient]:
    """An API client whose database work joins the rolled-back test transaction."""
    with TestClient(make_app(db_session)) as test_client:
        yield test_client


@pytest.fixture
def committed_client(make_app: Callable[..., FastAPI]) -> Iterator[tuple[TestClient, str]]:
    """A client using real per-request sessions that commit, plus a unique email.

    Use when behaviour depends on separate transactions (persistence across
    requests, row locks). Any user created with the email is deleted afterwards.
    """
    try:
        with database.engine.connect() as connection:
            schema_ready = inspect(connection).has_table("users")
    except OperationalError as error:
        reason = str(error.orig).splitlines()[-1].strip()
        pytest.skip(f"PostgreSQL is unavailable for integration tests: {reason}")
    if not schema_ready:
        pytest.fail("Database schema is missing; run `python -m alembic upgrade head`")

    email = f"committed-{uuid4().hex}@example.com"
    try:
        with TestClient(make_app()) as client:
            yield client, email
    finally:
        with database.SessionFactory() as session:
            session.execute(delete(User).where(User.email == email))
            session.commit()
