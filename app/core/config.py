"""Application configuration loaded from environment variables."""

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

LOCAL_DATABASE_URL = "postgresql+psycopg://auth:auth-local-only@localhost:5432/auth"
LOCAL_REDIS_URL = "redis://localhost:6379/0"
# The placeholder shipped in .env.example; it is public and must never sign real tokens.
EXAMPLE_SECRET_KEY = "replace-with-at-least-32-random-characters"

# Comma-separated in the environment, e.g. AUTH_CORS_ALLOWED_ORIGINS=https://a.com,https://b.com
CommaSeparated = Annotated[list[str], NoDecode]


class Environment(StrEnum):
    """Supported application environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Validated application settings."""

    app_name: str = "Authentication API"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    secret_key: SecretStr | None = None
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_ttl_days: int = Field(default=30, ge=1, le=365)
    email_verification_token_ttl_hours: int = Field(default=24, ge=1, le=168)
    password_reset_token_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    database_url: SecretStr = SecretStr(LOCAL_DATABASE_URL)
    redis_url: SecretStr = SecretStr(LOCAL_REDIS_URL)
    frontend_base_url: AnyHttpUrl = AnyHttpUrl("http://localhost:3000")
    frontend_verify_email_path: str = Field(default="/verify-email", pattern=r"^/")
    frontend_reset_password_path: str = Field(default="/reset-password", pattern=r"^/")
    email_provider: Literal["development"] = "development"
    email_from_address: str = "Authentication API <no-reply@localhost>"
    email_outbox_dir: Path | None = None
    email_task_max_retries: int = Field(default=5, ge=0, le=20)
    celery_task_always_eager: bool = False
    refresh_cookie_name: str = Field(default="refresh_token", pattern=r"^[A-Za-z0-9_\-]+$")
    refresh_cookie_path: str = Field(default="/api/v1/auth", pattern=r"^/")
    # None keeps the cookie host-only; set a domain only to share it across subdomains.
    refresh_cookie_domain: str | None = None
    refresh_cookie_secure: bool = True
    refresh_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    # Browser origins allowed to call the API with credentials. Empty disables CORS.
    cors_allowed_origins: CommaSeparated = []
    # Accepted Host headers. ["*"] accepts any host and is rejected in production.
    trusted_hosts: CommaSeparated = ["*"]
    # None exposes /docs and /openapi.json everywhere except production.
    docs_enabled: bool | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AUTH_",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("cors_allowed_origins", "trusted_hosts", mode="before")
    @classmethod
    def split_comma_separated(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("cors_allowed_origins")
    @classmethod
    def validate_cors_origins(cls, origins: list[str]) -> list[str]:
        """Credentialed CORS needs explicit origins without paths."""
        for origin in origins:
            if origin == "*":
                raise ValueError("AUTH_CORS_ALLOWED_ORIGINS cannot contain '*' with credentials")
            url = AnyHttpUrl(origin)
            if url.path not in (None, "", "/") or url.query or url.fragment:
                raise ValueError(f"CORS origin must not include a path: {origin}")
        return [origin.rstrip("/") for origin in origins]

    @property
    def expose_docs(self) -> bool:
        if self.docs_enabled is not None:
            return self.docs_enabled
        return self.environment is not Environment.PRODUCTION

    @model_validator(mode="after")
    def validate_refresh_cookie(self) -> "Settings":
        """Browsers reject SameSite=None cookies that are not also Secure."""
        if self.refresh_cookie_samesite == "none" and not self.refresh_cookie_secure:
            raise ValueError("AUTH_REFRESH_COOKIE_SAMESITE=none requires a secure cookie")
        return self

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        """Reject missing or local-only secrets in production."""
        if self.environment is not Environment.PRODUCTION:
            return self

        if not self.refresh_cookie_secure:
            raise ValueError("AUTH_REFRESH_COOKIE_SECURE must be enabled in production")

        secret = self.secret_key.get_secret_value() if self.secret_key else ""
        if len(secret) < 32:
            raise ValueError("AUTH_SECRET_KEY must contain at least 32 characters in production")
        if secret == EXAMPLE_SECRET_KEY:
            raise ValueError("AUTH_SECRET_KEY must not be the .env.example placeholder")

        if self.debug:
            raise ValueError("AUTH_DEBUG must be disabled in production")

        if not self.trusted_hosts or "*" in self.trusted_hosts:
            raise ValueError("AUTH_TRUSTED_HOSTS must list the API's hostnames in production")

        if any(not origin.startswith("https://") for origin in self.cors_allowed_origins):
            raise ValueError("AUTH_CORS_ALLOWED_ORIGINS must use https in production")

        if self.database_url.get_secret_value() == LOCAL_DATABASE_URL:
            raise ValueError("AUTH_DATABASE_URL must be overridden in production")

        if self.redis_url.get_secret_value() == LOCAL_REDIS_URL:
            raise ValueError("AUTH_REDIS_URL must be overridden in production")

        if self.frontend_base_url.scheme != "https":
            raise ValueError("AUTH_FRONTEND_BASE_URL must use https in production")

        if self.celery_task_always_eager:
            raise ValueError("AUTH_CELERY_TASK_ALWAYS_EAGER must be disabled in production")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide validated settings instance."""
    return Settings()
