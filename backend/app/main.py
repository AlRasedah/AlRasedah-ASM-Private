"""Exteriq ASM API application."""

from __future__ import annotations

import logging
import os
import time
import uuid

from asm_sensors import eventlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app import __version__
from app.core.config import get_settings
from app.core.context import RequestContext, set_context
from app.core.errors import AppError
from app.core.logging import configure_logging, request_id_var
from app.core.rate_limit import get_rate_limiter

log = logging.getLogger("app")
access = logging.getLogger("exteriq.access")
# One structured event per request (method, route template, status, duration). The native
# install turns it on and gunicorn's own text access log off; Docker keeps gunicorn's.
_LOG_REQUESTS = os.environ.get("ASM_LOG_REQUESTS", "false").lower() == "true"


def _field_name(err: dict) -> str | None:
    """Last named location segment ("body" → "email" → "email"); None for whole-body errors."""
    names = [str(p) for p in err.get("loc", ()) if isinstance(p, str) and p not in ("body", "query", "path", "header")]
    return names[-1] if names else None


def _friendly_message(err: dict) -> str:
    """User-facing text for a pydantic error. Never echoes patterns or internal constraints."""
    field = _field_name(err) or ""
    kind = err.get("type", "")
    ctx = err.get("ctx") or {}
    if kind == "string_pattern_mismatch":
        return "Enter a valid email address" if "email" in field else "This value has an invalid format"
    if kind == "string_too_short":
        return f"Must be at least {ctx.get('min_length')} characters" if ctx.get("min_length") else "Too short"
    if kind == "string_too_long":
        return f"Must be at most {ctx.get('max_length')} characters" if ctx.get("max_length") else "Too long"
    if kind == "missing":
        return "This field is required"
    if kind == "extra_forbidden":
        return "Unexpected field"
    if kind in ("enum", "literal_error"):
        return "Choose one of the listed options"
    if kind.startswith(("int_", "float_", "decimal_")) or kind in ("greater_than", "greater_than_equal", "less_than",
                                                                     "less_than_equal"):
        return str(err.get("msg", "Invalid number")).replace("Input should be", "Must be")
    if kind.startswith(("uuid_", "datetime_", "date_", "bool_", "url_")):
        return "This value has an invalid format"
    msg = str(err.get("msg", "Invalid value"))
    # Value errors raised by our own validators carry a readable message after this prefix.
    return msg.removeprefix("Value error, ")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
            "frame-ancestors 'none'")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if incoming.isalnum() and len(incoming) <= 64 else uuid.uuid4().hex
        ctx = RequestContext(request_id=rid, ip=request.client.host if request.client else None,
                             user_agent=request.headers.get("user-agent"))
        set_context(ctx)
        request_id_var.set(rid)
        # A fresh correlation context per request; authentication adds tenant and user.
        token = eventlog.bind(request_id=rid, correlation_id=rid)
        try:
            return await self._handle(request, call_next, rid, ctx)
        finally:
            eventlog.reset(token)

    async def _handle(self, request: Request, call_next: RequestResponseEndpoint, rid: str,
                      ctx: RequestContext) -> Response:
        started = time.monotonic()

        s = get_settings()
        if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/v1/health"):
            key = request.headers.get("authorization", "")[-24:] or ctx.ip or "anon"
            if not get_rate_limiter().hit(f"api:{key}", s.api_rate_limit_per_minute, 60):
                return JSONResponse({"error": {"code": "rate_limited", "message": "Too many requests"}},
                                    status_code=429, headers={"Retry-After": "60", "X-Request-ID": rid})
        response = await call_next(request)
        if _LOG_REQUESTS:
            route = request.scope.get("route")
            access.info("%s %s %s", request.method, getattr(route, "path", "unmatched"), response.status_code,
                        extra={"event": "http.request", "method": request.method,
                               "route": getattr(route, "path", "unmatched"), "http_status": response.status_code,
                               "duration_ms": round((time.monotonic() - started) * 1000)})
        response.headers["X-Request-ID"] = rid
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        docs = request.url.path.startswith(("/api/docs", "/api/redoc"))
        response.headers.setdefault("Content-Security-Policy", DOCS_CSP if docs else API_CSP)
        if s.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response


def create_app() -> FastAPI:
    s = get_settings()
    configure_logging(s.log_level, s.log_json, service="api")
    if os.environ.get("ASM_HEARTBEAT", "true").lower() != "false":
        from app.observability.health import start_heartbeat

        start_heartbeat("api")
    app = FastAPI(
        title="Exteriq ASM API",
        version=__version__,
        description="Continuous External Attack Surface Management — discover, monitor and prioritize "
                    "internet-facing assets and exposures.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    @app.exception_handler(AppError)
    async def app_error(_: Request, exc: AppError) -> JSONResponse:
        body: dict = {"code": exc.code, "message": exc.message}
        if exc.details is not None:
            body["details"] = exc.details
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        return JSONResponse({"error": body}, status_code=exc.status_code, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [{"loc": list(e.get("loc", [])), "field": _field_name(e), "msg": _friendly_message(e),
                    "type": e.get("type")} for e in exc.errors()]
        return JSONResponse({"error": {"code": "validation_failed", "message": "Please check the highlighted values",
                                       "details": details}}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error: %s", type(exc).__name__)
        return JSONResponse({"error": {"code": "internal_error", "message": "An unexpected error occurred"}},
                            status_code=500)

    app.add_middleware(RequestContextMiddleware)
    if s.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=True,
                           allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"])

    from app.api.v1.router import api_router

    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
