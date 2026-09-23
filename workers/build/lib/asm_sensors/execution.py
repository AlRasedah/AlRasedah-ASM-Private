"""Safe subprocess execution for scanner binaries.

Rules enforced here:

* Commands are executed with ``create_subprocess_exec`` – never through a shell.
* The executable must be on the adapter's allowlist and is resolved to an
  absolute path via ``PATH`` lookup.
* Every argument must be a ``str`` without NUL bytes.
* A minimal environment is passed (no inherited secrets from the worker).
* Wall-clock timeout with process-group kill, and a hard cap on captured output.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024
_SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "TEMP", "TMP")


class ExecutionError(RuntimeError):
    pass


class BinaryNotFound(ExecutionError):
    pass


@dataclass
class ProcessResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    duration: float
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def resolve_binary(name: str, allowed: Sequence[str]) -> str:
    if name not in allowed:
        raise ExecutionError(f"binary {name!r} is not on the allowlist")
    override = os.environ.get(f"ASM_BIN_{name.upper().replace('-', '_')}")
    path = override or shutil.which(name)
    if not path:
        raise BinaryNotFound(f"{name} is not installed in this sensor worker")
    return path


def minimal_env(extra: Mapping[str, str] | None = None, home: str | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    if home:
        env["HOME"] = home
    for k, v in (extra or {}).items():
        if not isinstance(k, str) or not isinstance(v, str) or "\x00" in v:
            raise ExecutionError("invalid environment entry")
        env[k] = v
    return env


async def _drain(stream: asyncio.StreamReader | None, limit: int) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    size = 0
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        if size < limit:
            keep = chunk[: limit - size]
            chunks.append(keep)
            size += len(keep)
            if len(keep) < len(chunk):
                truncated = True
        else:
            truncated = True  # keep draining so the child never blocks on a full pipe
    return b"".join(chunks), truncated


def _kill(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        if sys.platform != "win32":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass


async def run_process(
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    stdin_data: bytes | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
) -> ProcessResult:
    args = list(argv)
    if not args:
        raise ExecutionError("empty argv")
    for a in args:
        if not isinstance(a, str) or "\x00" in a:
            raise ExecutionError("every argument must be a string without NUL bytes")
    started = time.monotonic()
    kwargs: dict[str, object] = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True  # own process group -> killable as a unit
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=dict(env) if env is not None else minimal_env(),
        **kwargs,  # type: ignore[arg-type]
    )

    async def _communicate() -> tuple[tuple[bytes, bool], tuple[bytes, bool]]:
        if stdin_data is not None and proc.stdin is not None:
            proc.stdin.write(stdin_data)
            await proc.stdin.drain()
            proc.stdin.close()
        out, err = await asyncio.gather(
            _drain(proc.stdout, max_output_bytes), _drain(proc.stderr, 1024 * 1024)
        )
        await proc.wait()
        return out, err

    timed_out = False
    try:
        (stdout, out_trunc), (stderr, err_trunc) = await asyncio.wait_for(_communicate(), timeout=timeout)
    except TimeoutError:
        timed_out = True
        _kill(proc)
        try:
            await asyncio.wait_for(proc.wait(), timeout=10)
        except TimeoutError:
            pass
        stdout, out_trunc, stderr, err_trunc = b"", False, b"timed out", False
    except asyncio.CancelledError:
        _kill(proc)
        raise
    return ProcessResult(
        argv=args,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        duration=time.monotonic() - started,
        timed_out=timed_out,
        stdout_truncated=out_trunc,
        stderr_truncated=err_trunc,
    )
