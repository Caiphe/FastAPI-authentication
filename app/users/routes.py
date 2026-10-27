"""User HTTP endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.core.exceptions import ErrorResponse
from app.rbac.catalog import PermissionKey
from app.rbac.dependencies import AuthorizationContext, require_permission
from app.users.schemas import CurrentUserResponse, UserResponse

router = APIRouter(prefix="/users", tags=["users"])

ProfileReaderDep = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.PROFILE_READ))
]


@router.get(
    "/me",
    response_model=CurrentUserResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
    },
)
def read_current_user(context: ProfileReaderDep) -> CurrentUserResponse:
    """Return the authenticated user's profile, roles, and effective permissions."""
    profile = UserResponse.model_validate(context.user)
    return CurrentUserResponse(
        **profile.model_dump(),
        roles=list(context.authorization.roles),
        effective_permissions=list(context.authorization.permissions),
    )
