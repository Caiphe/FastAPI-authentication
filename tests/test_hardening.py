"""Middleware, documentation exposure, log redaction, OpenAPI contract, and errors."""

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.dispatch import get_email_dispatcher
from app.core.config import Environment, Settings
from app.core.logging import REDACTED, redact
from app.core.middleware import request_hostname
from app.main import create_app
from tests.conftest import FakeDispatcher

PRODUCTION: dict[str, Any] = {
    "environment": Environment.PRODUCTION,
    "secret_key": "p" * 40,
    "database_url": "postgresql+psycopg://user:password@db.example.com/auth",
    "redis_url": "rediss://default:password@redis.example.com:6379/0",
    "frontend_base_url": "https://app.example.com",
    "trusted_hosts": ["api.example.com", "*.internal.example.com"],
    "cors_allowed_origins": ["https://app.example.com"],
}


def build(settings: Settings) -> FastAPI:
    application = create_app(settings)
    application.dependency_overrides[get_email_dispatcher] = lambda: FakeDispatcher()
    return application


@pytest.fixture
def production_client() -> Iterator[TestClient]:
    settings = Settings.model_validate(PRODUCTION)
    with TestClient(build(settings), base_url="https://api.example.com") as client:
        yield client


@pytest.fixture
def development_client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(build(settings)) as client:
        yield client


# Security headers


def test_security_headers_are_added_to_every_response(development_client: TestClient) -> None:
    for response in (
        development_client.get("/health"),
        development_client.get("/missing"),
        development_client.post("/api/v1/auth/login", content=b"{"),
    ):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "strict-transport-security" not in response.headers


def test_hsts_is_sent_only_in_production(production_client: TestClient) -> None:
    response = production_client.get("/health")

    assert response.headers["strict-transport-security"].startswith("max-age=63072000")


# Trusted hosts


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("api.example.com", "api.example.com"),
        ("API.example.com:8443", "api.example.com"),
        ("[::1]:8000", "[::1]"),
        ("::1", "::1"),
    ],
)
def test_request_hostname_strips_ports(header: str, expected: str) -> None:
    assert request_hostname(header) == expected


@pytest.mark.parametrize("host", ["api.example.com", "svc.internal.example.com"])
def test_trusted_hosts_are_accepted(production_client: TestClient, host: str) -> None:
    assert production_client.get("/health", headers={"host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example.net", "internal.example.com", "example.com"])
def test_untrusted_hosts_are_rejected_with_error_envelope(
    production_client: TestClient, host: str
) -> None:
    response = production_client.get("/health", headers={"host": host})

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "invalid_host",
            "message": "The request host is not allowed.",
            "details": None,
        }
    }
    assert response.headers["x-content-type-options"] == "nosniff"


def test_any_host_is_accepted_in_development(development_client: TestClient) -> None:
    assert development_client.get("/health", headers={"host": "anything.test"}).status_code == 200


# CORS


def test_cors_preflight_allows_configured_origin_with_credentials(
    production_client: TestClient,
) -> None:
    response = production_client.options(
        "/api/v1/auth/refresh",
        headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert "POST" in response.headers["access-control-allow-methods"]


def test_cors_ignores_unlisted_origins(production_client: TestClient) -> None:
    response = production_client.get("/health", headers={"origin": "https://evil.example.net"})

    assert "access-control-allow-origin" not in response.headers


def test_cors_is_disabled_without_configured_origins(development_client: TestClient) -> None:
    response = development_client.get("/health", headers={"origin": "http://localhost:3000"})

    assert "access-control-allow-origin" not in response.headers


# Documentation exposure


def test_docs_are_hidden_in_production(production_client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        response = production_client.get(path)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


def test_docs_are_available_in_development(development_client: TestClient) -> None:
    assert development_client.get("/docs").status_code == 200
    assert development_client.get("/openapi.json").status_code == 200


# Log redaction


@pytest.mark.parametrize(
    ("message", "secret"),
    [
        ("Authorization: Bearer abc.def-ghi", "abc.def-ghi"),
        ("token eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl leaked", "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"),
        ("cookie: refresh_token=Zm9vYmFyYmF6", "Zm9vYmFyYmF6"),
        ('payload {"password": "hunter2-hunter2"}', "hunter2-hunter2"),
        ("new_password=correct-horse-battery", "correct-horse-battery"),
        ("link https://app.example.com/verify-email#token=s3cr3tValue", "s3cr3tValue"),
        ("connecting to postgresql://auth:db-pass@db:5432/auth", "db-pass"),
        ("AUTH_SECRET_KEY secret_key=abcdefabcdef", "abcdefabcdef"),
    ],
)
def test_redact_removes_credentials(message: str, secret: str) -> None:
    redacted = redact(message)

    assert secret not in redacted
    assert REDACTED in redacted


def test_redact_leaves_ordinary_messages_alone() -> None:
    message = "User 7f0c registered; action token 1234 is no longer usable"

    assert redact(message) == message


def test_redaction_applies_to_all_loggers(
    development_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        logging.getLogger("third.party").warning("sending %s", "Bearer leaked-value-123")

    assert "leaked-value-123" not in caplog.text
    assert REDACTED in caplog.text


def test_application_info_logs_are_enabled(development_client: TestClient) -> None:
    assert logging.getLogger("app").getEffectiveLevel() == logging.INFO


# OpenAPI contract

EXPECTED_OPERATIONS = {
    ("get", "/health"),
    ("post", "/api/v1/auth/register"),
    ("post", "/api/v1/auth/verify-email"),
    ("post", "/api/v1/auth/resend-verification"),
    ("post", "/api/v1/auth/login"),
    ("post", "/api/v1/auth/refresh"),
    ("post", "/api/v1/auth/logout"),
    ("post", "/api/v1/auth/forgot-password"),
    ("post", "/api/v1/auth/reset-password"),
    ("get", "/api/v1/users/me"),
}
INTERNAL_FIELDS = {
    "hashed_password",
    "token_hash",
    "family_id",
    "replaced_by_id",
    "used_at",
    "revoked_at",
    "is_active",
    "updated_at",
    "user_id",
    "refresh_token",
}


@pytest.fixture
def openapi(development_client: TestClient) -> dict[str, Any]:
    spec: dict[str, Any] = development_client.get("/openapi.json").json()
    return spec


def test_openapi_exposes_exactly_the_intended_operations(openapi: dict[str, Any]) -> None:
    operations = {(method, path) for path, item in openapi["paths"].items() for method in item}

    assert operations == EXPECTED_OPERATIONS


def test_openapi_schemas_do_not_leak_internal_fields(openapi: dict[str, Any]) -> None:
    properties = {
        name
        for schema in openapi["components"]["schemas"].values()
        for name in schema.get("properties", {})
    }

    assert properties.isdisjoint(INTERNAL_FIELDS)
    assert set(openapi["components"]["schemas"]["UserResponse"]["properties"]) == {
        "id",
        "email",
        "is_verified",
        "created_at",
    }


def test_openapi_documents_errors_with_the_shared_envelope(openapi: dict[str, Any]) -> None:
    for path, item in openapi["paths"].items():
        for method, operation in item.items():
            for status, response in operation["responses"].items():
                if status.startswith(("4", "5")):
                    schema = response["content"]["application/json"]["schema"]
                    assert schema == {"$ref": "#/components/schemas/ErrorResponse"}, (
                        method,
                        path,
                        status,
                    )


def test_openapi_marks_secrets_as_password_fields(openapi: dict[str, Any]) -> None:
    schemas = openapi["components"]["schemas"]
    for schema, field in [
        ("RegisterRequest", "password"),
        ("LoginRequest", "password"),
        ("ResetPasswordRequest", "new_password"),
        ("ResetPasswordRequest", "token"),
        ("VerifyEmailRequest", "token"),
    ]:
        assert schemas[schema]["properties"][field]["format"] == "password"


def test_openapi_protects_current_user_with_bearer_auth(openapi: dict[str, Any]) -> None:
    assert openapi["paths"]["/api/v1/users/me"]["get"]["security"] == [{"HTTPBearer": []}]


# Error consistency


def assert_envelope(response: Any) -> None:
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message", "details"}
    assert isinstance(body["error"]["code"], str) and body["error"]["message"]


BODYLESS_ENDPOINTS = {"/api/v1/auth/refresh", "/api/v1/auth/logout"}


@pytest.mark.parametrize(
    "path",
    sorted(
        path
        for method, path in EXPECTED_OPERATIONS
        if method == "post" and path not in BODYLESS_ENDPOINTS
    ),
)
def test_every_json_endpoint_reports_validation_errors_consistently(
    development_client: TestClient, path: str
) -> None:
    response = development_client.post(
        path, content=b"not json", headers={"content-type": "application/json"}
    )

    assert response.status_code == 422
    assert_envelope(response)
    assert response.json()["error"]["code"] == "validation_error"


def test_framework_errors_use_the_envelope(development_client: TestClient) -> None:
    for response in (
        development_client.get("/api/v1/nope"),
        development_client.delete("/api/v1/auth/login"),
        development_client.get("/api/v1/users/me"),
        development_client.post("/api/v1/auth/refresh"),
    ):
        assert response.status_code in {401, 404, 405}
        assert_envelope(response)
        assert json.loads(response.text)
