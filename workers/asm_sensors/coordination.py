"""Cross-process coordination for sensor workers.

Two primitives, both scoped to one worker pool:

* :meth:`Coordinator.lease` – an exclusive, self-renewing lease on a shared
  resource. The ZAP adapters hold one for the whole job because a ZAP daemon's
  session, alert store, scanner options and Replacer rules are global: two jobs
  (possibly for two tenants) must never use the same daemon at the same time.
* :meth:`Coordinator.claim` – a first-writer-wins marker, used to recognise a
  redelivered sensor job so the same active traffic is not sent twice.

:class:`RedisCoordinator` is used by the sensor worker containers (the keys live
in the broker under the pool's own prefix, which its broker ACL allows);
:class:`LocalCoordinator` serves inline mode (development and tests), where
every sensor runs in one process.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any


class LeaseLost(RuntimeError):
    """The lease stopped being ours while the work was still running."""


class LeaseUnavailable(RuntimeError):
    """The resource stayed leased by another job for longer than we were willing to wait."""


class Coordinator(ABC):
    poll_interval: float = 2.0

    @abstractmethod
    def claim(self, key: str, ttl: int) -> bool:
        """Mark ``key`` as taken for ``ttl`` seconds; False if someone else already did."""

    @abstractmethod
    async def _try_acquire(self, name: str, token: str, ttl: int) -> bool: ...

    @abstractmethod
    async def _renew(self, name: str, token: str, ttl: int) -> bool: ...

    @abstractmethod
    async def _release(self, name: str, token: str) -> None: ...

    @contextlib.asynccontextmanager
    async def lease(self, name: str, *, ttl: int = 120, wait: float = 3600) -> AsyncIterator[asyncio.Event]:
        """Hold ``name`` exclusively for the duration of the block.

        The lease expires ``ttl`` seconds after the holder stops renewing it (a
        crashed worker never blocks the resource for longer than that).

        If renewal stops succeeding the lease is **lost**: another job may already
        hold it, so the body must stop touching the resource. The event yielded here
        is set, the body is cancelled, and the lease is not released — releasing it
        would hand away a lock whose new owner is someone else. Callers check the
        event before any cleanup that would disturb the resource.
        """
        token = secrets.token_hex(16)
        deadline = time.monotonic() + wait
        while not await self._try_acquire(name, token, ttl):
            if time.monotonic() >= deadline:
                raise LeaseUnavailable(f"{name} is in use by another job")
            await asyncio.sleep(self.poll_interval)

        lost = asyncio.Event()
        owner = asyncio.current_task()

        async def keepalive() -> None:
            while True:
                await asyncio.sleep(max(ttl / 3, 0.05))
                try:
                    held = await self._renew(name, token, ttl)
                except Exception:  # noqa: BLE001 - a broker hiccup is a lost lease like any other
                    held = False
                if not held:
                    lost.set()
                    if owner is not None:
                        owner.cancel()
                    return

        renewer = asyncio.create_task(keepalive())
        try:
            yield lost
        except asyncio.CancelledError:
            if not lost.is_set():
                raise
            raise LeaseLost(f"the lease on {name} was lost to another job") from None
        finally:
            renewer.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await renewer
            if not lost.is_set():
                await self._release(name, token)


class LocalCoordinator(Coordinator):
    """In-process coordinator (inline mode). Thread-safe: every inline job runs its
    own event loop, possibly on its own thread."""

    def __init__(self, poll_interval: float = 0.05) -> None:
        self.poll_interval = poll_interval
        self._lock = threading.Lock()
        self._leases: dict[str, tuple[str, float]] = {}
        self._claims: dict[str, float] = {}

    def claim(self, key: str, ttl: int) -> bool:
        now = time.monotonic()
        with self._lock:
            if self._claims.get(key, 0) > now:
                return False
            self._claims[key] = now + ttl
            return True

    async def _try_acquire(self, name: str, token: str, ttl: int) -> bool:
        now = time.monotonic()
        with self._lock:
            held = self._leases.get(name)
            if held and held[1] > now:
                return False
            self._leases[name] = (token, now + ttl)
            return True

    async def _renew(self, name: str, token: str, ttl: int) -> bool:
        with self._lock:
            held = self._leases.get(name)
            if not held or held[0] != token:
                return False
            self._leases[name] = (token, time.monotonic() + ttl)
            return True

    async def _release(self, name: str, token: str) -> None:
        with self._lock:
            held = self._leases.get(name)
            if held and held[0] == token:
                del self._leases[name]


_RENEW = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) end return 0"
_RELEASE = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0"


class RedisCoordinator(Coordinator):
    """Broker-backed coordinator for sensor worker containers.

    Every key is ``<prefix><name>``; the prefix is the pool's namespace
    (``asm.pool.<pool>.``), the only non-queue keys a pool's broker user may touch.
    """

    def __init__(self, url: str, prefix: str) -> None:
        self.url = url
        self.prefix = prefix
        self._sync: Any = None

    def _key(self, name: str) -> str:
        return self.prefix + name

    def _sync_client(self) -> Any:
        if self._sync is None:
            import redis

            self._sync = redis.Redis.from_url(self.url, socket_timeout=10)
        return self._sync

    def claim(self, key: str, ttl: int) -> bool:
        return bool(self._sync_client().set(self._key(key), "1", nx=True, ex=max(int(ttl), 1)))

    @contextlib.asynccontextmanager
    async def _client(self) -> AsyncIterator[Any]:
        import redis.asyncio as aioredis

        client = aioredis.Redis.from_url(self.url, socket_timeout=10)
        try:
            yield client
        finally:
            await client.aclose()

    async def _try_acquire(self, name: str, token: str, ttl: int) -> bool:
        async with self._client() as r:
            return bool(await r.set(self._key(name), token, nx=True, px=int(ttl * 1000)))

    async def _renew(self, name: str, token: str, ttl: int) -> bool:
        async with self._client() as r:
            return bool(await r.eval(_RENEW, 1, self._key(name), token, int(ttl * 1000)))

    async def _release(self, name: str, token: str) -> None:
        async with self._client() as r:
            await r.eval(_RELEASE, 1, self._key(name), token)


_local: LocalCoordinator | None = None


def local_coordinator() -> LocalCoordinator:
    global _local
    if _local is None:
        _local = LocalCoordinator()
    return _local
