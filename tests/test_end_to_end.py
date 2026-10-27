"""Complete integration path: API, PostgreSQL, Redis broker, and a real Celery worker.

Nothing is replaced. Emails travel through Redis to a worker subprocess, which
writes them to a temporary outbox; the test follows the links it finds there.
"""

import os
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from email import message_from_bytes
from email.message import Message
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, inspect
from sqlalchemy.exc import OperationalError

from app.core import database
from app.core.config import Settings
from app.main import create_app
from app.users.models import User
from app.worker import celery_app

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a brand new passphrase 2026"
TOKEN_IN_LINK = re.compile(r"#token=([\w-]+)")


def ping_workers() -> list[str]:
    replies = celery_app.control.ping(timeout=0.5) or []
    return [name for reply in replies for name in reply]


@pytest.fixture
def worker(tmp_path: Path) -> Iterator[Path]:
    """Start a dedicated worker that writes emails to a temporary outbox."""
    try:
        with database.engine.connect() as connection:
            assert inspect(connection).has_table("users"), "run `python -m alembic upgrade head`"
        existing = ping_workers()
    except (OperationalError, OSError) as error:
        pytest.skip(f"PostgreSQL or Redis is unavailable: {error}")
    if existing:
        pytest.skip(f"Stop the running Celery worker(s) first: {', '.join(existing)}")

    outbox = tmp_path / "outbox"
    node = f"e2e-{uuid4().hex[:8]}@localhost"
    environment = {
        **os.environ,
        "AUTH_DATABASE_URL": database.engine.url.render_as_string(hide_password=False),
        "AUTH_REDIS_URL": str(celery_app.conf.broker_url),
        "AUTH_EMAIL_OUTBOX_DIR": str(outbox),
    }
    log_path = tmp_path / "worker.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "celery",
                "-A",
                "app.worker",
                "worker",
                "--pool=threads",
                "--concurrency=2",
                "--loglevel=INFO",
                "-n",
                node,
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + 30
        while node not in ping_workers():
            if process.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"Celery worker did not start:\n{log_path.read_text()}")
        yield outbox
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        worker_log = log_path.read_text()
        assert "Traceback" not in worker_log, worker_log


def wait_for_email(outbox: Path, recipient: str, subject: str, count: int = 1) -> Message:
    """Return the ``count``-th matching message once the worker has written it."""
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        messages = [
            message_from_bytes(path.read_bytes())
            for path in sorted(outbox.glob("*.eml"), key=lambda path: path.stat().st_mtime)
        ]
        matching = [m for m in messages if m["To"] == recipient and m["Subject"] == subject]
        if len(matching) >= count:
            return matching[count - 1]
        time.sleep(0.1)
    pytest.fail(f"No '{subject}' email #{count} for {recipient} arrived")


def link_token(message: Message) -> str:
    text_part = next(part for part in message.walk() if part.get_content_type() == "text/plain")
    payload = text_part.get_payload(decode=True)
    assert isinstance(payload, bytes)
    match = TOKEN_IN_LINK.search(payload.decode())
    assert match is not None
    return match.group(1)


@pytest.fixture
def email() -> Iterator[str]:
    address = f"e2e-{uuid4().hex}@example.com"
    yield address
    with database.SessionFactory() as session:
        session.execute(delete(User).where(User.email == address))
        session.commit()


def test_complete_account_lifecycle_through_real_worker(
    worker: Path, settings: Settings, email: str
) -> None:
    with TestClient(create_app(settings), base_url="https://testserver") as client:
        credentials = {"email": email, "password": PASSWORD}

        # Register; the verification email goes through Redis to the worker.
        assert client.post("/api/v1/auth/register", json=credentials).status_code == 201
        verification = wait_for_email(worker, email, "Verify your email address")
        assert client.post("/api/v1/auth/login", json=credentials).status_code == 403

        # Resend replaces the first link.
        assert (
            client.post("/api/v1/auth/resend-verification", json={"email": email}).status_code
            == 202
        )
        replacement = wait_for_email(worker, email, "Verify your email address", count=2)
        stale, current = link_token(verification), link_token(replacement)
        assert client.post("/api/v1/auth/verify-email", json={"token": stale}).status_code == 400
        assert client.post("/api/v1/auth/verify-email", json={"token": current}).status_code == 200

        # Login, use the access token, rotate the refresh cookie, and log out.
        login = client.post("/api/v1/auth/login", json=credentials)
        assert login.status_code == 200
        bearer = {"Authorization": f"Bearer {login.json()['access_token']}"}
        assert client.get("/api/v1/users/me", headers=bearer).json()["is_verified"] is True
        refreshed = client.post("/api/v1/auth/refresh")
        assert refreshed.status_code == 200
        assert client.post("/api/v1/auth/logout").status_code == 204
        assert client.post("/api/v1/auth/refresh").status_code == 401

        # Recover the password; the reset ends the session started below.
        client.post("/api/v1/auth/login", json=credentials)
        assert client.post("/api/v1/auth/forgot-password", json={"email": email}).status_code == 202
        reset_email = wait_for_email(worker, email, "Reset your password")
        session_cookie = client.cookies.get("refresh_token")
        reset = client.post(
            "/api/v1/auth/reset-password",
            json={"token": link_token(reset_email), "new_password": NEW_PASSWORD},
        )
        assert reset.status_code == 200
        stolen = client.post(
            "/api/v1/auth/refresh", headers={"Cookie": f"refresh_token={session_cookie}"}
        )
        assert stolen.status_code == 401
        assert client.post("/api/v1/auth/login", json=credentials).status_code == 401
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": email, "password": NEW_PASSWORD}
            ).status_code
            == 200
        )
