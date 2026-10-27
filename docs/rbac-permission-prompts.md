# Seeded RBAC Implementation Prompts

These prompts implement the approved design in
[`docs/superpowers/specs/2026-10-27-seeded-rbac-design.md`](superpowers/specs/2026-10-27-seeded-rbac-design.md).
Run them in order against the same working tree. Each prompt assumes the previous prompt is
complete and passing.

## Execution rules

- Start every prompt by reading the approved design and the files relevant to that step.
- Preserve unrelated user changes. Do not reset, overwrite, or reformat unrelated files.
- Use test-driven development: add or update focused tests first, observe the expected failure,
  implement the smallest complete change, and rerun the focused tests.
- Follow the existing FastAPI, SQLAlchemy 2, Pydantic 2, Alembic, error-envelope, repository, and
  service patterns.
- Keep access JWTs identity-only. Authorization must be resolved from PostgreSQL on each request.
- Do not add dynamic role or permission CRUD, tenant boundaries, account-management endpoints, or
  unrelated refactoring.
- Run `python -m ruff format` only on files touched by the current prompt, unless a full-project
  format check shows an existing issue in those files.
- At the end of each prompt, report changed files, tests run, results, and any assumption or
  deviation. Do not begin the next prompt automatically.

## Prompt 1 — RBAC models, migration, and seed catalog

```text
Implement Prompt 1 of the seeded RBAC plan.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- app/core/database.py
- app/models.py
- app/users/models.py
- alembic/versions/20261025_01_initial_auth_schema.py
- alembic/versions/20261025_02_case_insensitive_email.py
- tests/test_migrations.py

Scope:
1. Create the app/rbac package and its SQLAlchemy persistence models for roles, permissions,
   role_permissions, and user_roles exactly as specified.
2. Add bidirectional relationships only where they improve normal queries. Resolve the two
   user_roles-to-users foreign keys explicitly so SQLAlchemy has no ambiguous joins.
3. Ensure Alembic imports all new model metadata through the project's existing model-loading
   mechanism.
4. Add the next Alembic migration. It must:
   - create all four tables, foreign keys, composite primary keys, and useful indexes;
   - seed stable explicit UUIDs for roles and permissions;
   - seed user and admin role-permission mappings;
   - backfill the user role for every existing user without creating duplicates;
   - downgrade cleanly by dropping only RBAC data/tables, not users.
5. Define centralized constants for the seeded role names and permission keys so later code does
   not scatter string literals. The database remains the authority for assignments.
6. Extend migration tests to verify schema structure, deletion rules, exact seed catalog, exact
   mappings, existing-user backfill, downgrade, and re-upgrade.

Do not add services, routes, authorization dependencies, CLI behavior, or registration changes in
this prompt.

Verification:
- python -m pytest tests/test_migrations.py
- python -m alembic check
- python -m ruff check app/rbac app/models.py tests/test_migrations.py alembic/versions
- python -m mypy

Completion criteria:
- The new migration works from an empty database and on a database containing existing users.
- Seeded values match the approved design exactly.
- Upgrade/downgrade/re-upgrade passes without data-definition errors.
- Focused tests and static checks pass.
```

## Prompt 2 — RBAC repositories, services, and errors

```text
Implement Prompt 2 of the seeded RBAC plan after Prompt 1 is complete.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- app/rbac/models.py and seeded constants
- app/auth/repository.py
- app/auth/service.py
- app/users/repository.py
- app/core/exceptions.py
- tests/conftest.py

Scope:
1. Add app/rbac/repository.py with focused SQLAlchemy queries for:
   - deterministic role and permission catalog listing;
   - role lookup by name and user lookup needed by RBAC operations;
   - assigned role names and distinct effective permission keys for a user;
   - paginated users with total count and optional normalized, case-insensitive email search;
   - idempotent role assignment and removal;
   - counting active, verified administrators;
   - locking the seeded admin role row before last-administrator checks.
2. Add app/rbac/exceptions.py with application errors for permission denial, missing users, missing
   roles, ineligible administrator targets, and last-administrator removal. Use the shared error
   envelope conventions and the status codes approved in the design.
3. Add app/rbac/service.py as the transaction/business-rule boundary. It must support catalog
   reads, user reads, effective authorization reads, idempotent grant, and idempotent revoke.
4. For admin grants, require an active and verified target. Other seeded roles may be assigned to
   unverified accounts. The internal default-role assignment used later by registration must still
   support a new unverified user.
5. Protect last-admin removal transactionally. Lock the stable admin role row before counting and
   removing so concurrent removals serialize. Count only active, verified users holding admin.
6. Record assigned_by_user_id for HTTP-style assignments and allow null for system/CLI/default
   assignments. Never expose that audit value through public service DTOs.
7. Add focused repository/service integration tests, including multi-role permission union,
   deterministic ordering, pagination/search, idempotency, eligibility, transaction rollback, and
   last-admin protection. Add a concurrent-removal test if it fits cleanly here; otherwise leave a
   clearly named test for Prompt 5, not a TODO comment.

Do not add HTTP routes, FastAPI dependencies, CLI parsing, or README changes in this prompt.

Verification:
- python -m pytest tests/test_rbac_repository.py tests/test_rbac_service.py
- python -m ruff check app/rbac tests/test_rbac_repository.py tests/test_rbac_service.py
- python -m mypy

Completion criteria:
- Business rules have one service implementation reusable by HTTP and CLI.
- Effective permissions are queried from PostgreSQL and are not token claims or process caches.
- Idempotent mutations and last-admin safety are covered by tests.
- Focused tests and static checks pass.
```

## Prompt 3 — Registration, permission dependencies, and `/users/me`

```text
Implement Prompt 3 of the seeded RBAC plan after Prompts 1–2 are complete.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- app/auth/dependencies.py
- app/auth/service.py
- app/core/security.py
- app/users/routes.py
- app/users/schemas.py
- app/rbac/service.py
- tests/test_auth_registration.py
- tests/test_auth_login.py
- tests/test_auth_flow.py

Scope:
1. Change registration so every new account receives the seeded user role in the same database
   transaction as user and verification-token creation. If the seeded role is missing, roll back
   the entire registration and surface a server-side configuration failure without committing a
   partial account or token.
2. Add app/rbac/dependencies.py with a reusable, typed permission dependency factory. It must build
   on the existing authenticated-user dependency, query current roles/permissions from PostgreSQL,
   and return a useful authorization context to route handlers.
3. Do not cache authorization between requests. Reuse within a single request is allowed if done
   through FastAPI dependency caching.
4. Require profile:read on GET /api/v1/users/me.
5. Introduce a separate current-user response schema that preserves id, email, is_verified, and
   created_at and adds sorted roles and sorted effective_permissions. Keep the registration
   response shape unchanged.
6. Update direct-user test fixtures only where needed so tests represent valid RBAC state; do not
   weaken the new permission check to preserve old fixtures.
7. Add tests for default assignment, registration rollback, missing authentication, permission
   denial, multi-role effective permissions, deterministic response ordering, and immediate grant
   or revoke behavior while reusing the same access token.
8. Confirm decoded JWT claims remain exactly sub, iat, exp, and jti. Add a regression assertion if
   existing security tests do not already enforce this strictly.

Do not add administration routes or CLI commands in this prompt.

Verification:
- python -m pytest tests/test_auth_registration.py tests/test_auth_login.py tests/test_auth_flow.py tests/test_security.py tests/test_rbac_dependencies.py
- python -m ruff check app/auth app/users app/rbac tests
- python -m mypy

Completion criteria:
- Registration atomically grants user.
- /users/me is permission-protected and exposes only approved authorization information.
- An existing JWT observes role changes on its next request.
- JWT contents remain identity-only.
- Focused tests and static checks pass.
```

## Prompt 4 — Read-only administration API

```text
Implement Prompt 4 of the seeded RBAC plan after Prompts 1–3 are complete.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- app/main.py
- app/users/routes.py
- app/users/schemas.py
- app/rbac/dependencies.py
- app/rbac/service.py
- app/core/exceptions.py

Scope:
1. Add typed Pydantic response schemas and app/rbac/routes.py for:
   - GET /api/v1/admin/permissions, requiring roles:read;
   - GET /api/v1/admin/roles, requiring roles:read;
   - GET /api/v1/admin/users, requiring users:read;
   - GET /api/v1/admin/users/{user_id}, requiring users:read.
2. Register the router in the application factory under the existing API prefix.
3. Return roles with sorted permission keys and return catalog entries in deterministic key/name
   order.
4. For the user list, use offset pagination with offset default 0, limit default 50, and limit
   range 1–100. Return items, total, offset, and limit. Support an optional email query that is
   trimmed, normalized, and matched case-insensitively as a substring.
5. Admin user responses may include id, email, is_active, is_verified, created_at, and sorted role
   names. Do not expose password hashes, tokens, assigned_by_user_id, or other internal state.
6. Use 404 user_not_found for an unknown user and the existing validation envelope for malformed
   UUIDs or query parameters.
7. Add endpoint tests for successful responses, exact response shape, sorting, pagination, search,
   empty results, 401, 403, 404, and 422. Verify a user with only one required permission can call
   the relevant endpoint without having an admin-name special case.

Do not add assignment endpoints or CLI commands in this prompt.

Verification:
- python -m pytest tests/test_rbac_admin_read.py tests/test_errors.py tests/test_hardening.py
- python -m ruff check app/rbac app/main.py tests/test_rbac_admin_read.py
- python -m mypy

Completion criteria:
- All four read endpoints match the approved routes and permissions.
- Responses are deterministic, paginated where specified, and free of sensitive/audit fields.
- Permission checks are capability-based, not role-name checks.
- Focused tests and static checks pass.
```

## Prompt 5 — Role assignment API and concurrency safety

```text
Implement Prompt 5 of the seeded RBAC plan after Prompts 1–4 are complete.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- app/rbac/routes.py
- app/rbac/service.py
- app/rbac/repository.py
- app/rbac/exceptions.py
- tests/test_auth_refresh.py for existing concurrency-test patterns

Scope:
1. Add:
   - PUT /api/v1/admin/users/{user_id}/roles/{role_name};
   - DELETE /api/v1/admin/users/{user_id}/roles/{role_name}.
   Both require roles:assign and return 204 with no response body.
2. Pass the authenticated administrator's user ID to the service as assigned_by_user_id on grants.
3. Preserve idempotency: granting an existing assignment and removing an absent assignment both
   return 204 and do not create duplicate/audit-noise records.
4. Return the approved shared-envelope failures:
   - 404 user_not_found for an unknown target;
   - 404 role_not_found for an unknown role;
   - 409 when granting admin to an inactive or unverified account;
   - 409 when removing admin would leave no active, verified administrator.
5. Ensure all failures roll back cleanly and do not partially mutate assignments.
6. Add integration tests for authorization, success, exact 204 responses, audit attribution,
   idempotency, each failure, self-removal when another eligible admin exists, immediate effects
   with an already-issued JWT, and two concurrent last-admin removals. The concurrency test must
   prove at least one active, verified administrator remains after both requests complete.
7. If the service implementation from Prompt 2 needs adjustment to meet real route behavior, keep
   business rules in the service rather than duplicating them in route handlers.

Do not add CLI commands or documentation in this prompt.

Verification:
- python -m pytest tests/test_rbac_admin_assignments.py tests/test_rbac_service.py
- python -m pytest tests/test_auth_refresh.py
- python -m ruff check app/rbac tests/test_rbac_admin_assignments.py tests/test_rbac_service.py
- python -m mypy

Completion criteria:
- HTTP assignments are idempotent, audited, and immediately effective.
- Last-admin protection remains correct under concurrent requests.
- All response codes and envelopes match the design.
- Focused tests and static checks pass.
```

## Prompt 6 — Administrator bootstrap CLI

```text
Implement Prompt 6 of the seeded RBAC plan after Prompts 1–5 are complete.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- app/core/config.py
- app/core/database.py
- app/rbac/service.py
- app/users/schemas.py
- pyproject.toml

Scope:
1. Add an executable app/cli.py supporting exactly:
   - python -m app.cli grant-role --email admin@example.com --role admin
   - python -m app.cli revoke-role --email admin@example.com --role admin
2. Prefer the standard library argparse module unless an already-installed project dependency
   materially improves the implementation. Do not add a package solely for two commands.
3. Normalize email through the existing normalization function, open and close a configured
   SQLAlchemy session safely, and call the same RBAC service methods used by HTTP routes.
4. CLI assignments use assigned_by_user_id=None. Enforce the same admin eligibility and last-admin
   rules as HTTP.
5. Make both operations idempotent and print concise, non-sensitive outcomes.
6. Use stable exit behavior:
   - 0 for success, including an already-satisfied state;
   - 2 for command-line parsing/validation errors;
   - 3 for unknown users or roles;
   - 4 for business-rule conflicts such as ineligible or last-admin operations;
   - 1 for unexpected database/application failures.
7. Do not print connection URLs, password hashes, tokens, tracebacks, or secret settings in normal
   CLI error output.
8. Add tests for parsing, email normalization, successful grant/revoke, idempotency, null audit
   actor, not-found errors, both conflict types, database rollback, exit codes, and output
   redaction. Include at least one subprocess-level smoke test of python -m app.cli.

Do not update README or broaden the CLI in this prompt.

Verification:
- python -m pytest tests/test_cli.py
- python -m ruff check app/cli.py tests/test_cli.py
- python -m mypy

Completion criteria:
- The documented bootstrap command works against the configured database.
- CLI and HTTP enforce the same role-management rules.
- Failures are safe, actionable, and represented by stable exit codes.
- Focused tests and static checks pass.
```

## Prompt 7 — End-to-end flow and documentation

```text
Implement Prompt 7 of the seeded RBAC plan after Prompts 1–6 are complete.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- README.md
- tests/test_end_to_end.py
- all new RBAC routes, schemas, dependencies, services, and CLI code

Scope:
1. Extend the end-to-end test to cover:
   - registration automatically assigning user;
   - verification and login;
   - /users/me returning user plus profile:read;
   - bootstrap or equivalent service setup granting admin;
   - catalog and user administration access;
   - granting and revoking a role;
   - immediate authorization changes while an existing access token is reused.
2. Keep the existing real PostgreSQL, Redis, worker, email verification, refresh, reset, and logout
   lifecycle intact. Avoid making the end-to-end test order-dependent on development data.
3. Update README.md with:
   - the seeded roles and permissions table;
   - the migration command required to install RBAC schema/data;
   - the register, verify, then grant-role bootstrap workflow;
   - both CLI commands and exit-code meanings;
   - all six administration endpoints and their required permissions;
   - the expanded /users/me response;
   - an example require_permission dependency for future protected routes;
   - immediate database-backed authorization semantics and the identity-only JWT guarantee;
   - last-administrator protection;
   - the migration-based workflow for adding future roles or permissions.
4. Update the project layout and API reference without claiming dynamic RBAC management.
5. Ensure documentation examples use the project's actual API prefix and command style.

Verification:
- python -m pytest tests/test_end_to_end.py
- python -m ruff format --check .
- python -m ruff check .
- python -m mypy

Completion criteria:
- The real end-to-end lifecycle demonstrates RBAC without weakening existing authentication tests.
- README behavior and examples exactly match the implementation.
- Focused tests and static checks pass.
```

## Prompt 8 — Final integration and security review

```text
Perform the final integration and security review for the seeded RBAC implementation after
Prompts 1–7 are complete. Fix defects found, but do not add new features.

Read first:
- docs/superpowers/specs/2026-10-27-seeded-rbac-design.md
- git diff and every changed file
- README.md

Review checklist:
1. Compare the complete diff to every requirement and non-goal in the approved design.
2. Confirm there is no role-name bypass, wildcard permission, authorization data in JWTs,
   cross-request permission cache, dynamic catalog mutation, or sensitive/audit-field exposure.
3. Confirm all protected endpoints return 401 for missing/invalid authentication and 403
   permission_denied for an authenticated user lacking permission.
4. Confirm registration and migrations cannot leave partially initialized RBAC state.
5. Confirm every mutation has a clear transaction boundary and rollback behavior.
6. Confirm concurrent last-admin removals cannot eliminate every active, verified administrator.
7. Confirm deterministic response ordering, validated pagination, normalized search, idempotency,
   foreign-key behavior, and uniqueness constraints.
8. Confirm logs, errors, CLI output, and test failures do not reveal secrets, tokens, password
   hashes, connection credentials, or internal audit fields.
9. Remove dead code and accidental duplication introduced by the implementation. Do not perform
   unrelated refactors.

Run the complete verification suite with PostgreSQL and Redis available:
- docker compose up -d --wait
- python -m alembic upgrade head
- python -m pytest
- python -m ruff format --check .
- python -m ruff check .
- python -m mypy
- python -m alembic check

Also perform two manual smoke checks:
- Run python -m app.cli --help and verify both commands are discoverable.
- Open /openapi.json through a test client and verify the six administration endpoints, security
  requirements, response schemas, and documented error responses are present.

Completion criteria:
- The full test and quality suite passes.
- The implementation matches the approved design with no unresolved TODOs or placeholders.
- Report all commands and results, plus any remaining operational caveat.
```
