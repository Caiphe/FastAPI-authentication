"""Shared test fixtures."""

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, inspect, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.auth.dispatch import get_email_dispatcher
from app.core import database
from app.core.config import Environment, Settings
from app.core.security import create_access_token
from app.email.tasks import EmailDispatchError
from app.main import create_app
from app.rbac import repository as rbac_repository
from app.rbac.catalog import PermissionKey, RoleName
from app.rbac.models import Role, UserRole
from app.rbac.service import RbacService
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


def make_user(
    session: Session,
    email: str | None = None,
    *,
    roles: tuple[RoleName, ...] = (),
    is_active: bool = True,
    is_verified: bool = True,
) -> User:
    """Stage a user holding ``roles``. The password hash is a placeholder; mint tokens directly."""
    user = User(
        email=email or f"rbac-{uuid4().hex}@example.com",
        hashed_password="hash",
        is_active=is_active,
        is_verified=is_verified,
    )
    session.add(user)
    session.flush()
    for name in roles:
        role = rbac_repository.get_role_by_name(session, name)
        assert role is not None
        session.add(UserRole(user_id=user.id, role_id=role.id))
    session.flush()
    return user


@pytest.fixture
def committed_admins() -> Iterator[list[User]]:
    """Two committed, active, verified administrators, deleted afterwards."""
    tag = uuid4().hex
    try:
        with database.SessionFactory() as session:
            users = [make_user(session, f"admin-{i}-{tag}@example.com") for i in range(2)]
            service = RbacService(session)
            for user in users:
                service.grant_role(user.id, RoleName.ADMIN)
    except OperationalError as error:
        reason = str(error.orig).splitlines()[-1].strip()
        pytest.skip(f"PostgreSQL is unavailable for integration tests: {reason}")
    try:
        yield users
    finally:
        with database.SessionFactory() as session:
            session.execute(delete(User).where(User.email.contains(tag)))
            session.commit()


def bearer(settings: Settings, user: User) -> dict[str, str]:
    """Authorization headers with a freshly minted access token for ``user``."""
    return {"Authorization": f"Bearer {create_access_token(user.id, settings=settings)}"}


def holder_of(session: Session, settings: Settings, permission: PermissionKey) -> dict[str, str]:
    """Headers for a user whose only role grants exactly ``permission``, via a non-seeded role."""
    [granted] = [p for p in rbac_repository.list_permissions(session) if p.key == permission]
    role = Role(name=f"only-{uuid4().hex[:12]}", description="Test role", permissions=[granted])
    session.add(role)
    user = make_user(session)
    session.flush()
    session.add(UserRole(user_id=user.id, role_id=role.id))
    session.flush()
    return bearer(settings, user)


def assignment(session: Session, user_id: UUID, role: str) -> UserRole | None:
    """Re-read one role assignment from the database, bypassing the identity map."""
    return session.scalars(
        select(UserRole)
        .join(Role)
        .where(UserRole.user_id == user_id, Role.name == role)
        .execution_options(populate_existing=True)
    ).one_or_none()
