"""User API schemas and email normalization."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr


def normalize_email(address: str) -> str:
    """Return the canonical stored form of an email address."""
    return address.strip().lower()


NormalizedEmail = Annotated[EmailStr, AfterValidator(normalize_email)]


class UserResponse(BaseModel):
    """Public profile of a user account."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    is_verified: bool
    created_at: datetime


class CurrentUserResponse(UserResponse):
    """The authenticated user's profile with their roles and effective permissions."""

    roles: list[str]
    effective_permissions: list[str]
