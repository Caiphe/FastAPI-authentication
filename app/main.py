"""FastAPI application entry point."""

from fastapi import FastAPI
from pydantic import BaseModel

from app.auth.routes import router as auth_router
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import register_middleware
from app.users.routes import router as users_router


class HealthResponse(BaseModel):
    """Health-check response body."""

    status: str


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a FastAPI application instance."""
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings)
    docs = resolved_settings.expose_docs
    application = FastAPI(
        title=resolved_settings.app_name,
        debug=resolved_settings.debug,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    application.state.settings = resolved_settings
    register_exception_handlers(application)
    register_middleware(application, resolved_settings)
    application.include_router(auth_router, prefix=resolved_settings.api_v1_prefix)
    application.include_router(users_router, prefix=resolved_settings.api_v1_prefix)

    @application.get("/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    return application


app = create_app()
