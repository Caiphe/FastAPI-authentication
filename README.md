# FastAPI Authentication Starter

A reusable, API-only authentication service for browser-based clients: email and password accounts, email verification, short-lived JWT access tokens, rotating refresh-token cookies with reuse detection, and password recovery.

Built with Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, PostgreSQL, and Celery on Redis. It is one deployable API plus one Celery worker, organised as a feature-oriented modular monolith.

- [Quick start](#quick-start)
- [Everyday workflows](#everyday-workflows): PostgreSQL, Redis, the API, the worker, migrations
- [API reference](#api-reference)
- [Email and background jobs](#email-and-background-jobs)
- [Security](#security): defaults, production overrides, known limitations
- [Testing and quality checks](#testing-and-quality-checks)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)

## Quick start

Requirements: Python 3.11 or newer, and Docker with Compose v2.

```bash
# 1. Install the application and development tools
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

# 2. Create local configuration
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(48))'   # paste into AUTH_SECRET_KEY in .env

# 3. Start PostgreSQL and Redis, then create the schema
docker compose up -d --wait
python -m alembic upgrade head

# 4. Run the checks
python -m pytest

# 5. Start the API (terminal 1) and the worker (terminal 2)
python -m fastapi dev
celery -A app.worker worker --loglevel=INFO --pool=threads --concurrency=4
```

The API is now at <http://127.0.0.1:8000>, with interactive docs at <http://127.0.0.1:8000/docs>. Emails are not sent: the worker writes them to `.outbox/` as `.eml` files, which you can open to follow verification and reset links.

If `docker compose up` or the tests report `role "auth" does not exist`, another PostgreSQL is probably already using port 5432; see [Troubleshooting](#troubleshooting).

## Everyday workflows

### PostgreSQL and Redis

`compose.yaml` runs PostgreSQL 17 and Redis 7 with health checks and named volumes. Only infrastructure runs in Docker; the API and worker run from your virtual environment.

```bash
docker compose up -d --wait        # start and wait until healthy
docker compose ps                  # status and health
docker compose logs postgres redis # logs
docker compose down                # stop, keeping data
docker compose down --volumes      # stop and permanently delete local data
```

| Service | Address (defaults) | Credentials |
|---|---|---|
| PostgreSQL | `localhost:5432`, database `auth` | user `auth`, password `auth-local-only` |
| Redis | `localhost:6379`, database `0` | none |

Ports come from `POSTGRES_PORT` and `REDIS_PORT` in `.env`; keep `AUTH_DATABASE_URL` and `AUTH_REDIS_URL` in step with them. `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` take effect only when the PostgreSQL volume is first created. To connect a database client such as TablePlus, use the same host, port, user, password, and database as `AUTH_DATABASE_URL`.

### The API

```bash
python -m fastapi dev     # development server with auto-reload on http://127.0.0.1:8000
python -m fastapi run     # production-style server on 0.0.0.0:8000, no reload
```

`GET /health` returns `{"status": "ok"}`. Interactive docs live at `/docs` and `/redoc`, and the schema at `/openapi.json`; all three are disabled in production unless `AUTH_DOCS_ENABLED=true`. To call protected endpoints from `/docs`, log in, copy `access_token`, and paste it into **Authorize**.

### The worker

The worker delivers verification and password-reset emails. Without it, registration and recovery still succeed, but their emails wait in Redis until a worker starts.

```bash
celery -A app.worker worker --loglevel=INFO --pool=threads --concurrency=4
celery -A app.worker inspect ping     # check that a worker is reachable
```

The thread pool works on every platform and suits these I/O-bound tasks. On Linux you may use the default prefork pool by omitting `--pool` and `--concurrency`. On macOS with recent Python versions prefork can fail with `ValueError: not enough values to unpack (expected 3, got 0)`; use the thread pool instead.

For quick local experiments without a worker, set `AUTH_CELERY_TASK_ALWAYS_EAGER=true` to run tasks inside the API process. Production rejects this setting.

### Migrations

```bash
python -m alembic upgrade head                                     # apply all migrations
python -m alembic current                                          # show the applied revision
python -m alembic history                                          # list revisions
python -m alembic revision --autogenerate -m "describe the change" # after changing models
python -m alembic check                                            # fail if models and migrations differ
python -m alembic downgrade -1                                     # revert the latest revision
```

Always review autogenerated migrations; Alembic does not compare expression indexes such as `lower(email)`, so check those by hand.

## API reference

All endpoints except `/health` are under `/api/v1` (`AUTH_API_V1_PREFIX`). Request and response bodies are JSON.

| Method | Endpoint | Success | Failure responses |
|---|---|---|---|
| `POST` | `/auth/register` | `201` user profile | `409 email_already_registered`; `503 verification_email_unavailable` if the account was created but its email could not be queued |
| `POST` | `/auth/verify-email` | `200` | `400 invalid_token` for unknown, expired, reused, or replaced tokens |
| `POST` | `/auth/resend-verification` | `202` | none: the response is identical for every email address |
| `POST` | `/auth/login` | `200` access token, refresh cookie | `401 invalid_credentials`; `403 email_not_verified` or `403 account_disabled`, only after a correct password |
| `POST` | `/auth/refresh` | `200` access token, rotated cookie | `401 invalid_refresh_token`, which also clears the cookie |
| `POST` | `/auth/logout` | `204` | none: always succeeds and clears the cookie |
| `POST` | `/auth/forgot-password` | `202` | none: the response is identical for every email address |
| `POST` | `/auth/reset-password` | `200` | `400 invalid_token` |
| `GET` | `/users/me` | `200` user profile | `401 not_authenticated` or `401 invalid_token` |

Request validation failures on any endpoint return `422 validation_error`.

### Accounts

`register` takes `{"email", "password"}`. Email addresses are trimmed and lower-cased; a unique index on `lower(email)` enforces case-insensitive uniqueness in the database. Passwords must be 12 to 128 characters, with no composition rules. New accounts are active but unverified and cannot log in until they open the emailed link, whose token the frontend posts to `verify-email` as `{"token"}`. Verification tokens expire after `AUTH_EMAIL_VERIFICATION_TOKEN_TTL_HOURS` (24) and are single-use; `resend-verification` replaces any outstanding ones.

The user profile returned by `register` and `users/me` contains only `id`, `email`, `is_verified`, and `created_at`.

### Access tokens

`login` takes `{"email", "password"}` and returns:

```json
{"access_token": "<JWT>", "token_type": "bearer", "expires_in": 900}
```

Send the access token as `Authorization: Bearer <access_token>`. It is an HS256 JWT containing only `sub`, `iat`, `exp`, and `jti`, valid for `AUTH_ACCESS_TOKEN_TTL_MINUTES` (15). Every request re-checks that the user still exists, is active, and is verified. Token responses send `Cache-Control: no-store`.

### Refresh cookie and rotation

The refresh token never appears in a response body. It is a random opaque value, stored only as a SHA-256 hash, and sent as a cookie:

| Attribute | Default | Setting |
|---|---|---|
| Name | `refresh_token` | `AUTH_REFRESH_COOKIE_NAME` |
| Path | `/api/v1/auth`, so it is sent only to auth endpoints | `AUTH_REFRESH_COOKIE_PATH` |
| Domain | none (host-only) | `AUTH_REFRESH_COOKIE_DOMAIN` |
| `Secure` | on | `AUTH_REFRESH_COOKIE_SECURE` |
| `HttpOnly` | always on | not configurable |
| `SameSite` | `Lax` | `AUTH_REFRESH_COOKIE_SAMESITE` |
| `Max-Age` | 30 days | `AUTH_REFRESH_TOKEN_TTL_DAYS` |

`refresh` takes no body; call it with credentials, for example `fetch(url, {method: "POST", credentials: "include"})`. Each success marks the presented token used, issues a replacement in the same **family** with a fresh lifetime, and returns a new access token. Each login starts a new family, so each device or browser has its own.

Presenting a token that was already rotated or revoked is treated as theft and revokes its entire family: the attacker and the legitimate user must both log in again, while other devices are unaffected. Concurrent refreshes with one token are serialized by a row lock, so exactly one succeeds and the other triggers the reuse response. **Frontends must keep only one refresh request in flight at a time**, for example by sharing a single pending promise.

`logout` revokes the current family and clears the cookie.

### Password recovery

`forgot-password` takes `{"email"}`. For an active account it invalidates earlier reset links and emails a new one that expires after `AUTH_PASSWORD_RESET_TOKEN_TTL_MINUTES` (60). The frontend posts the token and the new password to `reset-password` as `{"token", "new_password"}`. A successful reset consumes the token, replaces the password, revokes **every** refresh-token family of the user, clears the refresh cookie on the current browser, and marks an unverified account as verified, since using the link proves control of the address.

### Errors

Every error, including 404, 405, invalid hosts, and unexpected 500s, uses one envelope. The one exception is `AUTH_DEBUG=true` (the `.env.example` default), where unexpected 500s return a plain-text traceback to aid local debugging; production forbids debug mode.

```json
{"error": {"code": "invalid_credentials", "message": "Email or password is incorrect.", "details": null}}
```

For `validation_error`, `details` lists each failing field's `loc`, `msg`, and `type`. Submitted values are never echoed back, so passwords and tokens cannot leak through error responses.

## Email and background jobs

Delivery goes through the `EmailProvider` interface in `app/email/provider.py`, which knows nothing about Celery or any vendor SDK. The only adapter is the development provider (`AUTH_EMAIL_PROVIDER=development`). It logs a message id, a masked recipient such as `j***@example.com`, and the subject, and when `AUTH_EMAIL_OUTBOX_DIR` is set it writes the full message to that directory. **It never sends email**: add an adapter for your provider before going live.

Links are built from `AUTH_FRONTEND_BASE_URL` plus `AUTH_FRONTEND_VERIFY_EMAIL_PATH` or `AUTH_FRONTEND_RESET_PASSWORD_PATH`, with the token in the URL fragment (`#token=...`) so it never reaches the frontend server's logs or `Referer` headers. The frontend reads it from `location.hash`.

The API queues emails only after its database transaction commits. A broker outage never rolls back an account: `register` returns `503` and the user can request another email later; `resend-verification` and `forgot-password` log the failure and keep their neutral response.

Email tasks are safe to retry and to deliver more than once:

- arguments are an action-token id and the raw token, never ORM objects, and the token is redacted from Celery's logged task representation;
- before sending, the worker re-checks that the token exists, matches its stored hash, is unused, unexpired, and still relevant, so stale or replaced links are never sent;
- an atomic Redis claim sends each token's email at most once, even when duplicate tasks run concurrently; a failed send releases the claim for the retry;
- provider, Redis, and PostgreSQL outages are retried with jittered exponential backoff (at most 5 minutes apart) up to `AUTH_EMAIL_TASK_MAX_RETRIES` times;
- tasks are acknowledged only after they finish, so a crashed worker's task is redelivered.

## Security

### Defaults

| Area | Behaviour |
|---|---|
| Passwords | Argon2 hashes; 12 to 128 characters |
| Login failures | One generic `401` for wrong passwords and unknown emails, with a dummy Argon2 check to equalise timing; account state is revealed only after a correct password |
| Opaque tokens | 256-bit random values; only SHA-256 hashes are stored; single-use and expiring |
| Access tokens | HS256 only; `sub`, `iat`, `exp`, `jti` required; 15 minutes |
| Refresh cookie | `Secure`, `HttpOnly`, `SameSite=Lax`, host-only, path-scoped; rotated on every use with family revocation on reuse |
| Enumeration | `resend-verification` and `forgot-password` respond identically for every address; `register` returns `409` as a deliberate usability trade-off |
| Responses | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` on every response, plus `Strict-Transport-Security` in production |
| CORS | Off until `AUTH_CORS_ALLOWED_ORIGINS` lists explicit origins; `*` is rejected because credentials are allowed |
| Logging | Application code never logs passwords, tokens, cookies, or secrets, and a process-wide filter redacts JWTs, bearer values, credential fields, and URL passwords from every log record as a safety net |

### Production overrides

Set `AUTH_ENVIRONMENT=production`. The application then **refuses to start** unless all of the following hold:

| Setting | Requirement |
|---|---|
| `AUTH_SECRET_KEY` | at least 32 characters and not the `.env.example` placeholder |
| `AUTH_DATABASE_URL`, `AUTH_REDIS_URL` | not the local defaults; use `rediss://` for TLS |
| `AUTH_TRUSTED_HOSTS` | the API's hostnames; `*` is rejected |
| `AUTH_CORS_ALLOWED_ORIGINS` | `https` origins only |
| `AUTH_FRONTEND_BASE_URL` | `https` |
| `AUTH_REFRESH_COOKIE_SECURE` | `true` |
| `AUTH_DEBUG` | `false` |
| `AUTH_CELERY_TASK_ALWAYS_EAGER` | `false` |

In production the interactive docs and OpenAPI schema are disabled by default and HSTS is sent. Also, outside what configuration can check:

- add a real `EmailProvider` adapter and set `AUTH_EMAIL_FROM_ADDRESS`;
- leave `AUTH_EMAIL_OUTBOX_DIR` unset, because the outbox stores live tokens;
- terminate TLS in front of the API and run Uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy address>`;
- rate-limit `login`, `register`, `resend-verification`, `forgot-password`, and `reset-password` at the proxy or gateway;
- keep Redis private: email task payloads carry raw action tokens until delivery;
- if you set `AUTH_REFRESH_COOKIE_SAMESITE=none` for a cross-site frontend, CSRF protection then rests entirely on CORS, so review `AUTH_CORS_ALLOWED_ORIGINS` carefully.

### Known limitations

- Access tokens are stateless: after logout or a password reset they stay valid until they expire (15 minutes by default).
- Rate limiting is out of scope for this starter.
- `resend-verification` and `forgot-password` do more work for existing accounts, so response timing could hint at whether an address is registered. Rate limiting reduces the value of this signal.
- Expired and revoked token rows are not cleaned up automatically; the `expires_at` indexes support a periodic cleanup job.

## Testing and quality checks

```bash
python -m pytest                       # everything
python -m pytest -m "not integration"  # only tests that need no services
python -m ruff format --check .
python -m ruff check .
python -m mypy                         # strict
python -m alembic check
```

Tests marked `integration` use the PostgreSQL and Redis from `compose.yaml` and need `python -m alembic upgrade head`; they are skipped with an explicit reason when those services are unreachable. They include:

- `tests/test_migrations.py`: applies every migration to a freshly created, empty database, verifies tables, constraints, indexes, and deletion rules, runs `alembic check`, downgrades to empty, upgrades again, and drops the database;
- `tests/test_end_to_end.py`: the complete account lifecycle through a real Celery worker subprocess, following the links it writes to a temporary outbox. It starts its own worker and is skipped if another worker is already consuming the queue, so **stop your development worker before running the full suite**.

Most integration tests run inside a transaction that is rolled back; tests that need real commits create uniquely named users and delete them afterwards. Tests never read your `.env` for their own settings, but they do use the database and Redis it points to.

## Project layout

```text
app/
├── main.py            application factory: routers, error handlers, middleware, logging
├── worker.py          Celery application
├── core/              shared infrastructure
│   ├── config.py      validated settings and production rules
│   ├── database.py    engine, session lifecycle, declarative base
│   ├── dependencies.py
│   ├── exceptions.py  error envelope and handlers
│   ├── logging.py     log configuration and redaction
│   ├── middleware.py  security headers, trusted hosts, CORS
│   └── security.py    password hashing, opaque tokens, JWTs
├── auth/              registration, verification, login, refresh, logout, recovery
│   ├── routes.py      HTTP concerns only
│   ├── service.py     use cases and transaction boundaries
│   ├── repository.py  persistence
│   ├── dependencies.py authenticated-user resolution
│   ├── dispatch.py    email dispatch boundary
│   ├── models.py, schemas.py, exceptions.py
├── users/             user model, profile schema, /users/me
└── email/             provider interface, templates, Celery tasks, delivery ledger
alembic/               migrations
tests/
```

Routes never query the database; services own transactions; repositories isolate persistence; every response uses an explicit Pydantic schema. Project construction followed the gated phases in [the build prompt](docs/build-auth-api-prompt.md).

## Troubleshooting

**`role "auth" does not exist` while the container is healthy.** Another PostgreSQL, often one installed with Homebrew, is bound to `127.0.0.1:5432` and receives `localhost` connections before Docker. The same can happen with Redis on 6379. Check:

```bash
lsof -nP -iTCP:5432 -sTCP:LISTEN
lsof -nP -iTCP:6379 -sTCP:LISTEN
```

Either stop the host service, or move the containers: set `POSTGRES_PORT=5433` and `REDIS_PORT=6380` in `.env`, change the ports in `AUTH_DATABASE_URL` and `AUTH_REDIS_URL` to match, and run `docker compose up -d --wait`.

**The same error after changing `POSTGRES_USER` or `POSTGRES_DB`.** These apply only when the volume is first created. Restore the old values, or reset the local database, which permanently deletes its data:

```bash
docker compose down
docker volume rm fastapi-auth-starter_postgres_data
docker compose up -d --wait
python -m alembic upgrade head
```

**No email arrives.** Check that a worker is running (`celery -A app.worker inspect ping`) and that `AUTH_EMAIL_OUTBOX_DIR` is set. The worker log reports `Email sent` or the reason it skipped a message.

**The end-to-end test is skipped.** A Celery worker is already running; stop it and run the tests again.
