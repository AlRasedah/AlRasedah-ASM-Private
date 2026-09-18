"""Fixed-window rate limiting backed by Redis, with an in-process fallback.

The fallback keeps development and tests working without Redis; production
deployments always have Redis, so limits are shared across API replicas.
"""

from __future__ import annotations

import logging
import threading
import time
from functools import lru_cache

from .config import get_settings

log = logging.getLogger(__name__)


class _MemoryWindow:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, tuple[int, float]] = {}

    def hit(self, key: str, window: int) -> int:
        now = time.monotonic()
        with self._lock:
            count, reset = self._data.get(key, (0, now + window))
            if now >= reset:
                count, reset = 0, now + window
            count += 1
            self._data[key] = (count, reset)
            if len(self._data) > 100_000:  # bound memory
                self._data = {k: v for k, v in self._data.items() if v[1] > now}
            return count

    def reset(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


class RateLimiter:
    def __init__(self, redis_url: str | None) -> None:
        self._memory = _MemoryWindow()
        self._redis = None
        self._redis_retry_at = 0.0
        if redis_url:
            try:
                import redis

                self._redis = redis.Redis.from_url(redis_url, socket_timeout=0.5, socket_connect_timeout=0.5)
            except Exception:  # noqa: BLE001
                self._redis = None

    def hit(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """Register a hit; return True if the caller is within the limit."""
        bucket = f"rl:{key}:{int(time.time() // window_seconds)}"
        count: int
        if self._redis is not None and time.monotonic() >= self._redis_retry_at:
            try:
                pipe = self._redis.pipeline()
                pipe.incr(bucket)
                pipe.expire(bucket, window_seconds + 1)
                count = int(pipe.execute()[0])
            except Exception:  # noqa: BLE001 - degrade to local limiting, never fail open silently
                log.warning("rate limiter: redis unavailable, using local windows for 30s")
                self._redis_retry_at = time.monotonic() + 30
                count = self._memory.hit(key, window_seconds)
        else:
            count = self._memory.hit(key, window_seconds)
        return count <= limit

    def clear(self, key: str) -> None:
        self._memory.reset(key)


@lru_cache
def get_rate_limiter() -> RateLimiter:
    s = get_settings()
    return RateLimiter(None if s.env == "test" else s.redis_url)
