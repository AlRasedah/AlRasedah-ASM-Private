"""A per-job forward proxy that decides every connection a browser makes.

Checking a hostname before starting a browser is not enough: the page can
redirect, load frames, scripts and images from anywhere, open WebSockets, and a
name can resolve differently a second later (DNS rebinding). So the browser gets
*no* network of its own — its resolver is disabled and every request must go
through this proxy — and the proxy, for each connection:

1. accepts only ``CONNECT host:port`` (TLS, WebSocket) or an absolute-form
   ``http://`` request, on an allowed port;
2. refuses hostnames in the scope's exclusions;
3. resolves the name itself and refuses it if *any* address is loopback,
   private, link-local (cloud metadata), reserved, or in an excluded range —
   including IPv4 hidden in IPv6 (mapped, 6to4, Teredo, NAT64);
4. connects to the exact address it just checked, so the decision and the
   connection can never refer to different addresses.

It also bounds the job: number of connections, bytes per response, bytes in
total, idle time. Blocked destinations are recorded as ``host:port: reason`` —
never a path or query string, which can carry tokens.

Runs in-process on 127.0.0.1 with an ephemeral port for exactly one job.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], Awaitable[list[IPAddr]]]

BLOCK_HEADER = "X-Egress-Blocked"
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_HEAD_LIMIT = 16 * 1024


async def system_resolve(host: str, timeout: float = 5.0) -> list[IPAddr]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout)
    except (OSError, TimeoutError, UnicodeError):
        return []
    out: list[IPAddr] = []
    for info in infos:
        try:
            a = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        except ValueError:
            continue
        if a not in out:
            out.append(a)
    return out


def _embedded(addr: IPAddr) -> list[IPAddr]:
    """The address itself plus any IPv4 address tunnelled inside it."""
    out: list[IPAddr] = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            out.append(addr.ipv4_mapped)
        if addr.sixtofour:
            out.append(addr.sixtofour)
        if addr.teredo:
            out.extend(addr.teredo)
        if any(addr in n for n in _NAT64):
            out.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    return out


# Refused even in lab mode (``allow_non_public``): link-local ranges carry the cloud
# instance-metadata services, whose answers include credentials.
ALWAYS_BLOCKED = tuple(ipaddress.ip_network(n) for n in (
    "169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "100.100.100.200/32"))


def address_verdict(addr: IPAddr, *, allow_non_public: bool, excluded: Sequence[IPNetwork]) -> str | None:
    """Why this address may not be contacted (None = it may)."""
    for a in _embedded(addr):
        if any(a.version == n.version and a in n for n in ALWAYS_BLOCKED):
            return f"link-local or metadata address {addr}"
        if not allow_non_public and (not a.is_global or a.is_multicast):
            return f"non-public address {addr}"
        if a.is_unspecified or a.is_multicast:
            return f"unusable address {addr}"
        if any(a.version == n.version and a in n for n in excluded):
            return f"excluded address {addr}"
    return None


def _domain_excluded(host: str, excluded_domains: Sequence[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in excluded_domains)


@dataclass
class EgressPolicy:
    allow_non_public: bool = False
    excluded_networks: list[IPNetwork] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    # Hosts no page needs but a browser contacts by itself (updates, sign-in, safe browsing).
    denied_domains: list[str] = field(default_factory=list)
    allowed_ports: frozenset[int] = frozenset({80, 443})
    max_connections: int = 300
    max_response_bytes: int = 5 * 1024 * 1024
    max_upload_bytes: int = 1024 * 1024
    max_total_bytes: int = 20 * 1024 * 1024
    connect_timeout: float = 5.0
    idle_timeout: float = 15.0


@dataclass
class EgressStats:
    connections: int = 0
    allowed: int = 0
    blocked: list[str] = field(default_factory=list)  # "host:port: reason", capped
    blocked_count: int = 0
    allowed_hosts: list[str] = field(default_factory=list)  # "host:port", capped
    bytes_down: int = 0
    bytes_up: int = 0
    limit_hit: str | None = None


class EgressProxy:
    def __init__(self, policy: EgressPolicy, resolver: Resolver | None = None) -> None:
        self.policy = policy
        self.resolver = resolver or system_resolve
        self.stats = EgressStats()
        self._server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self.port = 0

    # ----------------------------------------------------------- lifecycle
    async def start(self) -> int:
        self._server = await asyncio.start_server(self._accept, host="127.0.0.1", port=0, limit=_HEAD_LIMIT + 1)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
        for t in list(self._tasks):
            t.cancel()
        for t in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        self._tasks.clear()

    async def __aenter__(self) -> EgressProxy:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # ------------------------------------------------------------ decisions
    def _block(self, host: str, port: int, reason: str) -> str:
        self.stats.blocked_count += 1
        if len(self.stats.blocked) < 20:
            self.stats.blocked.append(f"{host}:{port}: {reason}")
        return reason

    async def authorize(self, host: str, port: int) -> tuple[IPAddr | None, str | None]:
        """The address to connect to, or why the destination is refused."""
        p = self.policy
        host = host.strip().strip("[]").lower().rstrip(".")
        if self.stats.connections > p.max_connections:
            self.stats.limit_hit = self.stats.limit_hit or "connection limit"
            return None, self._block(host, port, "connection limit reached")
        if port not in p.allowed_ports:
            return None, self._block(host, port, "port not allowed")
        try:
            literal: IPAddr | None = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is None:
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                return None, self._block(host, port, "invalid hostname")
            if _domain_excluded(host, p.excluded_domains):
                return None, self._block(host, port, "hostname excluded from scope")
            if _domain_excluded(host, p.denied_domains):
                return None, self._block(host, port, "browser background service")
            addrs = await self.resolver(host)
            if not addrs:
                return None, self._block(host, port, "does not resolve")
        else:
            addrs = [literal]
        for a in addrs:  # every address must be acceptable, not just the first
            reason = address_verdict(a, allow_non_public=p.allow_non_public, excluded=p.excluded_networks)
            if reason:
                return None, self._block(host, port, reason)
        self.stats.allowed += 1
        if len(self.stats.allowed_hosts) < 50 and f"{host}:{port}" not in self.stats.allowed_hosts:
            self.stats.allowed_hosts.append(f"{host}:{port}")
        return addrs[0], None

    # ------------------------------------------------------------- handling
    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            await self._handle(reader, writer)
        except (asyncio.CancelledError, ConnectionError, TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError, ValueError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            if task is not None:
                self._tasks.discard(task)

    async def _read_head(self, reader: asyncio.StreamReader) -> bytes:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.policy.idle_timeout)
        if len(head) > _HEAD_LIMIT:
            raise ValueError("request head too large")
        return head

    async def _refuse(self, writer: asyncio.StreamWriter, status: str, reason: str) -> None:
        body = f"Refused by egress policy: {reason}\n".encode()
        writer.write(f"HTTP/1.1 {status}\r\n{BLOCK_HEADER}: 1\r\nContent-Type: text/plain\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        with contextlib.suppress(Exception):
            await writer.drain()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await self._read_head(reader)
        self.stats.connections += 1
        line, _, rest = head.partition(b"\r\n")
        try:
            method, target, version = line.decode("latin-1").split(" ", 2)
        except ValueError:
            await self._refuse(writer, "400 Bad Request", "malformed request")
            return
        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            if not host or not port_s.isdigit():
                await self._refuse(writer, "400 Bad Request", "malformed CONNECT")
                return
            port, forward = int(port_s), b""
        else:
            try:
                u = urlsplit(target)
                port = u.port or 80
            except ValueError:
                await self._refuse(writer, "400 Bad Request", "malformed URL")
                return
            if u.scheme != "http" or not u.hostname:
                await self._refuse(writer, "403 Forbidden", self._block(u.hostname or "?", 0, "scheme not allowed"))
                return
            host = u.hostname
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            headers = [h for h in rest.split(b"\r\n") if h and not h.lower().startswith(
                (b"proxy-", b"connection:", b"keep-alive:"))]
            forward = (f"{method} {path} {version}\r\n".encode("latin-1") + b"\r\n".join(headers)
                       + b"\r\nConnection: close\r\n\r\n")
        addr, reason = await self.authorize(host, port)
        if addr is None:
            await self._refuse(writer, "403 Forbidden", reason or "refused")
            return
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(str(addr), port),
                                                self.policy.connect_timeout)
        except (OSError, TimeoutError):
            await self._refuse(writer, "502 Bad Gateway", "upstream unreachable")
            return
        try:
            if forward:
                up_w.write(forward)
                await up_w.drain()
            else:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            await self._pipe(reader, writer, up_r, up_w)
        finally:
            with contextlib.suppress(Exception):
                up_w.close()

    async def _pipe(self, c_r: asyncio.StreamReader, c_w: asyncio.StreamWriter,
                    u_r: asyncio.StreamReader, u_w: asyncio.StreamWriter) -> None:
        p = self.policy

        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter, down: bool) -> None:
            moved = 0
            limit = p.max_response_bytes if down else p.max_upload_bytes
            while True:
                chunk = await asyncio.wait_for(src.read(65536), p.idle_timeout)
                if not chunk:
                    break
                moved += len(chunk)
                if down:
                    self.stats.bytes_down += len(chunk)
                else:
                    self.stats.bytes_up += len(chunk)
                if moved > limit:
                    self.stats.limit_hit = self.stats.limit_hit or ("response size" if down else "upload size")
                    break
                if self.stats.bytes_down > p.max_total_bytes:
                    self.stats.limit_hit = self.stats.limit_hit or "total download size"
                    break
                dst.write(chunk)
                await dst.drain()

        tasks = [asyncio.ensure_future(copy(c_r, u_w, False)), asyncio.ensure_future(copy(u_r, c_w, True))]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
