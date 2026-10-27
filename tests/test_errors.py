"""Centralized error response tests that need no database."""

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.exceptions import EmailAlreadyRegisteredError
from app.users.schemas import normalize_email


@pytest.fixture
def api(make_app: Callable[..., FastAPI]) -> FastAPI:
    application = make_app()

    @application.get("/raise-app-error")
    def raise_app_error() -> None:
        raise EmailAlreadyRegisteredError(details={"field": "email"})

    @application.get("/raise-unexpected")
    def raise_unexpected() -> None:
        raise RuntimeError("secret internal detail")

    return application


@pytest.fixture
def anonymous_client(api: FastAPI) -> Iterator[TestClient]:
    with TestClient(api, raise_server_exceptions=False) as test_client:
        yield test_client


def test_normalize_email_trims_and_lowercases() -> None:
    assert normalize_email("  Jane.Doe@Example.COM ") == "jane.doe@example.com"


def test_app_errors_use_the_error_envelope(anonymous_client: TestClient) -> None:
    response = anonymous_client.get("/raise-app-error")

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "email_already_registered",
            "message": "An account with this email address already exists.",
            "details": {"field": "email"},
        }
    }


def test_unknown_route_uses_the_error_envelope(anonymous_client: TestClient) -> None:
    response = anonymous_client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "not_found", "message": "Not Found", "details": None}
    }


def test_wrong_method_uses_the_error_envelope(anonymous_client: TestClient) -> None:
    response = anonymous_client.get("/api/v1/auth/register")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"
    assert "POST" in response.headers["allow"]


def test_unexpected_errors_hide_internal_details(anonymous_client: TestClient) -> None:
    response = anonymous_client.get("/raise-unexpected")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "An unexpected error occurred.",
            "details": None,
        }
    }
    assert "secret internal detail" not in response.text


@pytest.mark.parametrize("password", ["x" * 11, "x" * 129])
def test_validation_errors_keep_field_details_without_echoing_input(
    anonymous_client: TestClient, password: str
) -> None:
    response = anonymous_client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": password},
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert {tuple(detail["loc"]) for detail in error["details"]} == {
        ("body", "email"),
        ("body", "password"),
    }
    assert all(set(detail) == {"loc", "msg", "type"} for detail in error["details"])
    assert password not in response.text
    assert "not-an-email" not in response.text


def test_malformed_json_is_a_validation_error(anonymous_client: TestClient) -> None:
    response = anonymous_client.post(
        "/api/v1/auth/register",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
