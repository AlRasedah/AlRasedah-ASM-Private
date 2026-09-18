"""Domain exceptions mapped to HTTP responses by the API layer."""

from __future__ import annotations


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, code: str | None = None, details: object | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details


class NotFound(AppError):
    status_code = 404
    code = "not_found"


class Forbidden(AppError):
    status_code = 403
    code = "forbidden"


class Unauthorized(AppError):
    status_code = 401
    code = "unauthorized"


class Conflict(AppError):
    status_code = 409
    code = "conflict"


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_failed"


class QuotaExceeded(AppError):
    status_code = 429
    code = "quota_exceeded"


class RateLimited(AppError):
    status_code = 429
    code = "rate_limited"


class ScopeViolation(AppError):
    status_code = 422
    code = "out_of_scope"
