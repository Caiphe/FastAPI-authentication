"""Reusable permission requirements for protected endpoints."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends

from app.auth.dependencies import CurrentUserDep
from app.core.dependencies import SessionDep
from app.rbac.catalog import PermissionKey
from app.rbac.service import Authorization, RbacService
from app.users.models import User


def get_rbac_service(session: SessionDep) -> RbacService:
    return RbacService(session)


RbacServiceDep = Annotated[RbacService, Depends(get_rbac_service)]


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """The authenticated user and the authorization loaded for this request."""

    user: User
    authorization: Authorization


def get_authorization_context(
    user: CurrentUserDep, service: RbacServiceDep
) -> AuthorizationContext:
    """Load the user's current roles and permissions from the database.

    FastAPI caches this per request, so several permission requirements on one
    route share a single lookup. Nothing is cached across requests.
    """
    return AuthorizationContext(user=user, authorization=service.get_authorization(user.id))


AuthorizationContextDep = Annotated[AuthorizationContext, Depends(get_authorization_context)]


def require_permission(permission: PermissionKey) -> Callable[..., AuthorizationContext]:
    """Build a dependency that admits only users holding ``permission``.

    Usage: ``Annotated[AuthorizationContext, Depends(require_permission(PermissionKey.X))]``.
    Missing or invalid credentials return 401; a missing permission returns 403.
    """

    def dependency(context: AuthorizationContextDep) -> AuthorizationContext:
        context.authorization.require(permission)
        return context

    return dependency
