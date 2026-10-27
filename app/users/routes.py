"""User HTTP endpoints."""

from fastapi import APIRouter, status

from app.auth.dependencies import CurrentUserDep
from app.core.exceptions import ErrorResponse
from app.users.schemas import UserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/me",
    response_model=UserResponse,
    responses={status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse}},
)
def read_current_user(user: CurrentUserDep) -> UserResponse:
    """Return the authenticated user's public profile."""
    return UserResponse.model_validate(user)
