# Seeded RBAC Design

## Purpose

Extend the authentication starter with database-backed role-based access control (RBAC).
The system must support reusable permission guards, immediate authorization changes for active
sessions, administrative role assignment, and an explicit way to bootstrap the first
administrator.

Success means:

- every registered user receives the seeded `user` role;
- a user may hold multiple roles, and effective permissions are the union of those roles;
- protected requests resolve permissions from PostgreSQL rather than trusting JWT claims;
- administrators can inspect the catalog and manage user-role assignments through HTTP;
- the first administrator can be created safely through a CLI command;
- role and permission definitions remain controlled, reviewable migration data.

## Scope

This change includes:

- seeded roles and permissions;
- role-to-permission and user-to-role persistence;
- authorization services and FastAPI dependencies;
- current-user authorization details;
- read-only catalog endpoints and user-role administration endpoints;
- administrator bootstrap and role-management CLI commands;
- migrations, tests, API documentation, and operational documentation.

This change does not include dynamic creation, editing, or deletion of role and permission
definitions. It also does not add account activation/deactivation endpoints, organization or
tenant boundaries, resource ownership policies, attribute-based rules, or permission claims in
access tokens.

## Authorization Model

The initial permission catalog is:

| Permission | Meaning |
| --- | --- |
| `profile:read` | Read the authenticated user's own profile. |
| `users:read` | List and inspect users through the administration API. |
| `roles:read` | List the role and permission catalog. |
| `roles:assign` | Assign and remove roles from users. |

The initial role catalog is:

| Role | Permissions |
| --- | --- |
| `user` | `profile:read` |
| `admin` | Every seeded permission |

A user can hold more than one role. Their effective permission set is the distinct union of all
permissions assigned through those roles. There is no special-case administrator bypass: an
administrator is authorized because the `admin` role maps to the required permissions.

The catalog is immutable through the API. Future catalog changes must be represented by reviewed
database migrations and corresponding model/test/documentation changes.

## Package Boundaries

Authorization will live in a dedicated `app/rbac/` package:

- `models.py` defines roles, permissions, and association records;
- `repository.py` contains persistence queries only;
- `service.py` owns authorization and role-assignment business rules and transactions;
- `dependencies.py` exposes reusable FastAPI permission requirements;
- `schemas.py` defines catalog, assignment, and effective-authorization responses;
- `exceptions.py` defines predictable RBAC errors;
- `routes.py` exposes the administration API.

Authentication remains responsible for proving identity and managing sessions. User registration
may call the RBAC repository or service to assign the default role within the account-creation
transaction. Both the HTTP administration routes and CLI use the same RBAC service so they enforce
identical assignment rules.

## Data Model

### `roles`

- UUID primary key
- unique, stable `name`
- human-readable `description`
- creation and update timestamps

### `permissions`

- UUID primary key
- unique, stable `key`
- human-readable `description`
- creation and update timestamps

### `role_permissions`

- `role_id` foreign key to `roles`, with cascade delete
- `permission_id` foreign key to `permissions`, with cascade delete
- composite primary key preventing duplicate mappings

### `user_roles`

- `user_id` foreign key to `users`, with cascade delete
- `role_id` foreign key to `roles`, with cascade delete
- `assigned_at` timestamp
- nullable `assigned_by_user_id` self-reference to `users`, using `SET NULL` on deletion
- composite primary key preventing duplicate assignments
- indexes supporting role membership and audit lookup

The nullable assigning-user field distinguishes system or CLI assignments from HTTP assignments.
It is internal audit data and must not appear in public responses.

The migration will use stable explicit identifiers for seeded records, create all constraints and
indexes, seed the catalog and mappings, and assign `user` to every existing account. Downgrade will
remove RBAC tables without deleting users. New registrations assign `user` in the same transaction
as account creation; a missing seeded role is a server configuration failure, not a partially
created account.

## Request Authorization Flow

Access JWTs remain identity-only and retain their current `sub`, `iat`, `exp`, and `jti` claims.
The existing authenticated-user dependency continues to verify the token and reload an active,
verified user from PostgreSQL.

Permission dependencies build on that identity check. A reusable dependency factory such as
`require_permission("roles:assign")` will load the user's effective permissions from PostgreSQL for
the current request and reject access unless the requested key is present. Permission results may
be reused within one request, but they must not be cached across requests. Consequently, a role
assignment or removal applies to the user's next request, including requests made with an already
issued access token.

Unauthenticated requests return the existing `401` responses. Authenticated requests without a
required permission return HTTP `403` in the shared error envelope:

```json
{
  "error": {
    "code": "permission_denied",
    "message": "You do not have permission to perform this action.",
    "details": null
  }
}
```

The response will not disclose unnecessary authorization internals.

## Current-User Response

`GET /api/v1/users/me` will require `profile:read`. Its response will preserve the existing public
profile fields and add sorted role names and sorted effective permission keys. Registration keeps
its current response shape by continuing to use the existing public user schema rather than the
expanded current-user schema.

## Administration API

All endpoints use the existing `/api/v1` prefix and error envelope.

| Method | Endpoint | Required permission | Behavior |
| --- | --- | --- | --- |
| `GET` | `/admin/permissions` | `roles:read` | List seeded permissions. |
| `GET` | `/admin/roles` | `roles:read` | List roles with their permission keys. |
| `GET` | `/admin/users` | `users:read` | Return a paginated user list with optional normalized email search. |
| `GET` | `/admin/users/{user_id}` | `users:read` | Return account state and assigned roles. |
| `PUT` | `/admin/users/{user_id}/roles/{role_name}` | `roles:assign` | Idempotently assign a role. |
| `DELETE` | `/admin/users/{user_id}/roles/{role_name}` | `roles:assign` | Idempotently remove a role. |

List responses use deterministic ordering. Pagination has validated bounds and includes enough
metadata for clients to request subsequent pages. Email search is case-insensitive and does not
expose password or token information.

Assignment endpoints return `204 No Content` both when they change the assignment and when the
requested final state already exists. Unknown users and roles return `404`. Malformed identifiers,
pagination, and search inputs return the existing `422 validation_error` envelope. Granting the
`admin` role to an inactive or unverified account returns `409`; other seeded roles may be assigned
before verification.

## Last-Administrator Protection

The HTTP API and CLI must refuse to remove the `admin` role from the last active, verified user who
holds it. The failure uses HTTP `409` for the API and a nonzero CLI exit code. The check and removal
must execute in one transaction with database locking that serializes concurrent removals, ensuring
two administrators cannot simultaneously remove each other and leave the system without an
administrator.

The protection applies only to removing the seeded `admin` role. Adding roles and removing other
roles do not need global serialization.

## CLI

The application exposes:

```bash
python -m app.cli grant-role --email admin@example.com --role admin
python -m app.cli revoke-role --email admin@example.com --role admin
```

Email input is normalized using the same logic as authentication. The commands use the configured
database, call the RBAC service, print concise results without sensitive data, and return nonzero
exit codes for unknown users, unknown roles, unsafe last-administrator removal, invalid input, or
database failures. Granting an existing assignment and revoking an absent assignment succeed.
CLI-created assignments have a null `assigned_by_user_id`.

The bootstrap workflow is: register an account, verify its email, then grant it the `admin` role
with the CLI. The grant command will reject inactive or unverified target accounts so the first
administrator is immediately usable and conforms to normal login requirements. This is the same
business rule used when the HTTP API grants the `admin` role.

## Testing Strategy

Tests will cover:

- complete migration upgrade/downgrade behavior, constraints, indexes, seed values, mappings, and
  existing-user backfill;
- automatic `user` assignment during registration and rollback if the seeded role is missing;
- direct and unioned permissions across one or multiple roles;
- immediate grant and revocation effects while reusing an existing access token;
- current-user roles and effective permissions without internal audit fields;
- every administration endpoint's success, `401`, `403`, `404`, `409`, validation, pagination,
  search, deterministic ordering, and idempotency behavior;
- concurrent attempts to remove the last administrator;
- CLI success, idempotency, normalization, error output, and exit codes;
- regression coverage for login, refresh, password reset, email tasks, middleware, error envelopes,
  and the full account lifecycle;
- formatting, linting, strict typing, Alembic consistency, and the complete pytest suite.

## Documentation and Delivery

The README will document the seeded catalog, permission guard pattern, current-user response,
administration endpoints, bootstrap CLI, last-administrator rule, and the migration-based process
for adding future roles or permissions.

The implementation will be broken into runnable, verification-oriented prompts in
`docs/rbac-permission-prompts.md`. Each prompt will identify prerequisites, exact scope, expected
tests, and completion criteria so it can be executed independently while preserving the decisions
in this specification.
