"""Names of the seeded roles and permissions.

The catalog itself is created by migrations, and role assignments live in the
database; these constants only keep code from repeating string literals.
"""

from enum import StrEnum


class RoleName(StrEnum):
    """Seeded role names."""

    USER = "user"
    ADMIN = "admin"


class PermissionKey(StrEnum):
    """Seeded permission keys."""

    PROFILE_READ = "profile:read"
    USERS_READ = "users:read"
    ROLES_READ = "roles:read"
    ROLES_ASSIGN = "roles:assign"
