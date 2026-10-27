"""End-to-end auth flow with a real session per request, as in production.

Other integration tests share one session with the service, so an uncommitted
change could still look persisted. Here every request commits independently.
"""

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FakeDispatcher

pytestmark = pytest.mark.integration

PASSWORD = "correct horse battery staple"


def test_register_verify_login_and_me_persist_across_requests(
    committed_client: tuple[TestClient, str], dispatcher: FakeDispatcher
) -> None:
    client, email = committed_client
    credentials = {"email": email, "password": PASSWORD}

    assert client.post("/api/v1/auth/register", json=credentials).status_code == 201
    before = client.post("/api/v1/auth/login", json=credentials)
    assert before.status_code == 403
    assert before.json()["error"]["code"] == "email_not_verified"

    token = dispatcher.queued[0].token
    assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 200
    assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 400

    login = client.post("/api/v1/auth/login", json=credentials)
    assert login.status_code == 200, login.text
    me = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["email"] == email
    assert me.json()["is_verified"] is True


def test_password_reset_persists_and_ends_sessions_across_requests(
    committed_client: tuple[TestClient, str], dispatcher: FakeDispatcher
) -> None:
    client, email = committed_client
    old = {"email": email, "password": PASSWORD}
    new = {"email": email, "password": "a brand new passphrase 2026"}
    client.post("/api/v1/auth/register", json=old)
    client.post("/api/v1/auth/verify-email", json={"token": dispatcher.queued[0].token})
    login = client.post("/api/v1/auth/login", json=old)
    refresh_cookie = {"Cookie": login.headers["set-cookie"].split(";")[0]}

    assert client.post("/api/v1/auth/forgot-password", json={"email": email}).status_code == 202
    reset = client.post(
        "/api/v1/auth/reset-password",
        json={"token": dispatcher.queued[-1].token, "new_password": new["password"]},
    )

    assert reset.status_code == 200
    assert client.post("/api/v1/auth/refresh", headers=refresh_cookie).status_code == 401
    assert client.post("/api/v1/auth/login", json=old).status_code == 401
    assert client.post("/api/v1/auth/login", json=new).status_code == 200
