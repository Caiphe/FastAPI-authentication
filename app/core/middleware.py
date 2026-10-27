"""HTTP middleware shared by every endpoint."""

from http import HTTPStatus

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Environment, Settings
from app.core.exceptions import error_response

SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
}
HSTS_HEADER = (b"strict-transport-security", b"max-age=63072000; includeSubDomains")


class SecurityHeadersMiddleware:
    """Add conservative security headers without overriding ones a route set."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.headers = dict(SECURITY_HEADERS)
        if hsts:
            self.headers[HSTS_HEADER[0]] = HSTS_HEADER[1]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(k, v) for k, v in self.headers.items() if k not in existing]
                message["headers"] = [*message.get("headers", []), *extra]
            await send(message)

        await self.app(scope, receive, send_with_headers)


class TrustedHostMiddleware:
    """Reject requests whose Host header is not allowed, using the error envelope.

    Entries may be exact hostnames or ``*.example.com`` to allow subdomains.
    Starlette's equivalent replies in plain text, bypassing the shared format.
    """

    def __init__(self, app: ASGIApp, *, allowed_hosts: list[str]) -> None:
        self.app = app
        self.exact = {host.lower() for host in allowed_hosts if not host.startswith("*.")}
        self.suffixes = tuple(host[1:].lower() for host in allowed_hosts if host.startswith("*."))

    def is_allowed(self, host: str) -> bool:
        return host in self.exact or (bool(self.suffixes) and host.endswith(self.suffixes))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        host = request_hostname(Headers(scope=scope).get("host", ""))
        if self.is_allowed(host):
            await self.app(scope, receive, send)
            return

        response = error_response(
            HTTPStatus.BAD_REQUEST, "invalid_host", "The request host is not allowed."
        )
        await response(scope, receive, send)


def request_hostname(host_header: str) -> str:
    """Strip the port from a Host header, including bracketed IPv6 forms."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[: host.find("]") + 1] if "]" in host else host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def register_middleware(application: FastAPI, settings: Settings) -> None:
    """Install middleware. The last one added is outermost, so the order is:
    security headers -> trusted host -> CORS -> application.
    """
    if settings.cors_allowed_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            # Required so browsers send and accept the refresh-token cookie.
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
        )
    if settings.trusted_hosts != ["*"]:
        application.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    application.add_middleware(
        SecurityHeadersMiddleware, hsts=settings.environment is Environment.PRODUCTION
    )
