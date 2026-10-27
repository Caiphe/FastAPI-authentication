"""Administration API schemas for the role catalog and user accounts."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class PermissionResponse(BaseModel):
    """A seeded permission."""

    model_config = ConfigDict(from_attributes=True)

    key: str
    description: str


class RoleResponse(BaseModel):
    """A seeded role with its permission keys, sorted."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    description: str
    permissions: list[str]


class AdminUserResponse(BaseModel):
    """Account state visible to administrators. Never includes credentials or audit data."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    roles: list[str]


class AdminUserPageResponse(BaseModel):
    """One page of users, ordered by email."""

    model_config = ConfigDict(from_attributes=True)

    items: list[AdminUserResponse]
    total: int
    offset: int
    limit: int
