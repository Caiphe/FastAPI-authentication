"""Configuration tests."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import (
    EXAMPLE_SECRET_KEY,
    LOCAL_DATABASE_URL,
    LOCAL_REDIS_URL,
    Environment,
    Settings,
)

# A complete, valid production configuration. Rejection tests override one value.
VALID_PRODUCTION: dict[str, Any] = {
    "environment": Environment.PRODUCTION,
    "secret_key": "a" * 32,
    "database_url": "postgresql+psycopg://user:password@db.example.com/auth",
    "redis_url": "rediss://default:password@redis.example.com:6379/0",
    "frontend_base_url": "https://app.example.com",
    "trusted_hosts": ["api.example.com"],
    "cors_allowed_origins": ["https://app.example.com"],
}


def test_development_settings_have_safe_defaults() -> None:
    settings = Settings.model_validate({"environment": Environment.DEVELOPMENT, "secret_key": None})

    assert settings.app_name == "Authentication API"
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.secret_key is None
    assert settings.debug is False
    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_ttl_minutes == 15
    assert settings.refresh_token_ttl_days == 30
    assert settings.email_verification_token_ttl_hours == 24
    assert settings.password_reset_token_ttl_minutes == 60
    assert settings.database_url.get_secret_value() == LOCAL_DATABASE_URL
    assert settings.redis_url.get_secret_value() == LOCAL_REDIS_URL
    assert settings.cors_allowed_origins == []
    assert settings.trusted_hosts == ["*"]
    assert settings.expose_docs is True


def test_valid_production_configuration_is_accepted() -> None:
    settings = Settings.model_validate(VALID_PRODUCTION)

    assert settings.secret_key is not None
    assert settings.secret_key.get_secret_value() == "a" * 32
    assert settings.expose_docs is False


def test_production_docs_can_be_enabled_explicitly() -> None:
    assert Settings.model_validate({**VALID_PRODUCTION, "docs_enabled": True}).expose_docs


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"secret_key": None}, "AUTH_SECRET_KEY"),
        ({"secret_key": "a" * 31}, "AUTH_SECRET_KEY"),
        ({"secret_key": EXAMPLE_SECRET_KEY}, "placeholder"),
        ({"database_url": LOCAL_DATABASE_URL}, "AUTH_DATABASE_URL"),
        ({"redis_url": LOCAL_REDIS_URL}, "AUTH_REDIS_URL"),
        ({"frontend_base_url": "http://app.example.com"}, "AUTH_FRONTEND_BASE_URL"),
        ({"celery_task_always_eager": True}, "AUTH_CELERY_TASK_ALWAYS_EAGER"),
        ({"refresh_cookie_secure": False}, "AUTH_REFRESH_COOKIE_SECURE"),
        ({"debug": True}, "AUTH_DEBUG"),
        ({"trusted_hosts": ["*"]}, "AUTH_TRUSTED_HOSTS"),
        ({"trusted_hosts": []}, "AUTH_TRUSTED_HOSTS"),
        ({"cors_allowed_origins": ["http://app.example.com"]}, "AUTH_CORS_ALLOWED_ORIGINS"),
    ],
    ids=lambda value: next(iter(value)) if isinstance(value, dict) else None,
)
def test_production_rejects_unsafe_settings(override: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings.model_validate({**VALID_PRODUCTION, **override})


def test_settings_read_connection_urls_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = "postgresql+psycopg://test:test@database:5432/test"
    redis_url = "redis://cache:6379/1"
    monkeypatch.setenv("AUTH_DATABASE_URL", database_url)
    monkeypatch.setenv("AUTH_REDIS_URL", redis_url)

    settings = Settings()

    assert settings.database_url.get_secret_value() == database_url
    assert settings.redis_url.get_secret_value() == redis_url


def test_list_settings_are_comma_separated_in_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AUTH_CORS_ALLOWED_ORIGINS", "https://app.example.com/, http://localhost:3000"
    )
    monkeypatch.setenv("AUTH_TRUSTED_HOSTS", "api.example.com, localhost")

    settings = Settings()

    assert settings.cors_allowed_origins == ["https://app.example.com", "http://localhost:3000"]
    assert settings.trusted_hosts == ["api.example.com", "localhost"]


@pytest.mark.parametrize(
    "origin", ["*", "https://app.example.com/path", "https://app.example.com?x=1", "not a url"]
)
def test_cors_origins_must_be_explicit_origins(origin: str) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({"cors_allowed_origins": [origin]})


def test_refresh_cookie_defaults_are_secure() -> None:
    settings = Settings.model_validate({"environment": Environment.DEVELOPMENT})

    assert settings.refresh_cookie_name == "refresh_token"
    assert settings.refresh_cookie_path == "/api/v1/auth"
    assert settings.refresh_cookie_domain is None
    assert settings.refresh_cookie_secure is True
    assert settings.refresh_cookie_samesite == "lax"


def test_insecure_refresh_cookie_is_allowed_for_local_development() -> None:
    settings = Settings.model_validate(
        {"environment": Environment.DEVELOPMENT, "refresh_cookie_secure": False}
    )

    assert settings.refresh_cookie_secure is False


def test_samesite_none_requires_secure_cookie() -> None:
    with pytest.raises(ValidationError, match="AUTH_REFRESH_COOKIE_SAMESITE"):
        Settings.model_validate({"refresh_cookie_samesite": "none", "refresh_cookie_secure": False})
