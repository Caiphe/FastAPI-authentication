"""Predictable authorization and role-management failures."""

from http import HTTPStatus

from app.core.exceptions import AppError


class PermissionDeniedError(AppError):
    """Deliberately says nothing about which permission was missing."""

    status_code = HTTPStatus.FORBIDDEN
    code = "permission_denied"
    message = "You do not have permission to perform this action."


class DefaultRoleMissingError(AppError):
    """The seeded ``user`` role is absent, so new accounts cannot be initialized."""

    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    code = "configuration_error"
    message = "The service is not configured correctly."


class UserNotFoundError(AppError):
    status_code = HTTPStatus.NOT_FOUND
    code = "user_not_found"
    message = "The user does not exist."


class RoleNotFoundError(AppError):
    status_code = HTTPStatus.NOT_FOUND
    code = "role_not_found"
    message = "The role does not exist."


class IneligibleAdministratorError(AppError):
    status_code = HTTPStatus.CONFLICT
    code = "admin_target_ineligible"
    message = "The admin role can only be granted to an active, verified account."


class LastAdministratorError(AppError):
    status_code = HTTPStatus.CONFLICT
    code = "last_administrator"
    message = "The admin role cannot be removed from the last active, verified administrator."
