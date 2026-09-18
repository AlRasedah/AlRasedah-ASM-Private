"""Per-request context (client IP, user agent, request id, actor) via contextvars."""

from __future__ import annotations

import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class RequestContext:
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ip: str | None = None
    user_agent: str | None = None
    user_id: uuid.UUID | None = None
    actor: str | None = None
    tenant_id: uuid.UUID | None = None


_ctx: ContextVar[RequestContext | None] = ContextVar("asm_request_context", default=None)


def get_context() -> RequestContext:
    ctx = _ctx.get()
    if ctx is None:
        ctx = RequestContext()
        _ctx.set(ctx)
    return ctx


def set_context(ctx: RequestContext) -> None:
    _ctx.set(ctx)
