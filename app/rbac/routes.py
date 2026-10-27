"""Administration HTTP endpoints for the role catalog, user accounts, and role assignment."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.core.exceptions import ErrorResponse
from app.rbac.catalog import PermissionKey
from app.rbac.dependencies import AuthorizationContext, RbacServiceDep, require_permission
from app.rbac.schemas import (
    AdminUserPageResponse,
    AdminUserResponse,
    PermissionResponse,
    RoleResponse,
)

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_403_FORBIDDEN: {"model": ErrorResponse},
    },
)

VALIDATION_ERROR: dict[int | str, dict[str, Any]] = {
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse},
}
USER_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
}
ASSIGNMENT_ERRORS: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {
        "model": ErrorResponse,
        "description": "`user_not_found` or `role_not_found`.",
    },
    status.HTTP_409_CONFLICT: {
        "model": ErrorResponse,
        "description": "`admin_target_ineligible` or `last_administrator`.",
    },
    **VALIDATION_ERROR,
}
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100

RolesReaderDep = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_READ))
]
UsersReaderDep = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.USERS_READ))
]
RoleAssignerDep = Annotated[
    AuthorizationContext, Depends(require_permission(PermissionKey.ROLES_ASSIGN))
]
RoleNamePath = Annotated[str, Path(max_length=64)]


@router.get("/permissions", response_model=list[PermissionResponse])
def list_permissions(_: RolesReaderDep, service: RbacServiceDep) -> list[PermissionResponse]:
    """List the seeded permissions, ordered by key."""
    return [PermissionResponse.model_validate(p) for p in service.list_permissions()]


@router.get("/roles", response_model=list[RoleResponse])
def list_roles(_: RolesReaderDep, service: RbacServiceDep) -> list[RoleResponse]:
    """List the seeded roles with their permission keys, ordered by name."""
    return [RoleResponse.model_validate(role) for role in service.list_roles()]


@router.get("/users", response_model=AdminUserPageResponse, responses=VALIDATION_ERROR)
def list_users(
    _: UsersReaderDep,
    service: RbacServiceDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    email: Annotated[
        str | None,
        Query(max_length=320, description="Case-insensitive email substring."),
    ] = None,
) -> AdminUserPageResponse:
    """Page through users ordered by email, optionally filtered by email."""
    page = service.list_users(offset=offset, limit=limit, email=email)
    return AdminUserPageResponse.model_validate(page)


@router.get(
    "/users/{user_id}",
    response_model=AdminUserResponse,
    responses={**USER_NOT_FOUND, **VALIDATION_ERROR},
)
def get_user(user_id: UUID, _: UsersReaderDep, service: RbacServiceDep) -> AdminUserResponse:
    """Return one user's account state and assigned roles."""
    return AdminUserResponse.model_validate(service.get_user(user_id))


@router.put(
    "/users/{user_id}/roles/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses=ASSIGNMENT_ERRORS,
)
def grant_role(
    user_id: UUID, role_name: RoleNamePath, context: RoleAssignerDep, service: RbacServiceDep
) -> Response:
    """Assign a role. Succeeds without change if the user already holds it."""
    service.grant_role(user_id, role_name, assigned_by_user_id=context.user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/users/{user_id}/roles/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses=ASSIGNMENT_ERRORS,
)
def revoke_role(
    user_id: UUID, role_name: RoleNamePath, _: RoleAssignerDep, service: RbacServiceDep
) -> Response:
    """Remove a role. Succeeds without change if the user does not hold it."""
    service.revoke_role(user_id, role_name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
