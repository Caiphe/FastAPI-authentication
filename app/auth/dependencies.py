"""Authenticated-user resolution for protected endpoints."""

from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.exceptions import NotAuthenticatedError
from app.auth.service import AuthServiceDep
from app.users.models import User

# auto_error=False lets missing or non-Bearer credentials use the shared error envelope.
bearer_scheme = HTTPBearer(auto_error=False, description="Access token from /auth/login")


def get_current_user(
    service: AuthServiceDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> User:
    """Require a valid ``Authorization: Bearer <access token>`` header."""
    if credentials is None:
        raise NotAuthenticatedError()
    return service.authenticate_access_token(credentials.credentials)


CurrentUserDep = Annotated[User, Depends(get_current_user)]
