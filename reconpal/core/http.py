"""Polite async HTTP client.

Two jobs: keep request volume low enough that we never degrade the target,
and refuse to send anything the Scope object has not approved. Both are
enforced here rather than in the modules, so a new module cannot forget.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .scope import Scope, ScopeError

DEFAULT_UA = "ReconPal/1.0 (authorised security testing; +https://github.com/amooryx/ReconPal)"


@dataclass
class RateLimiter:
    """Token bucket that backs off when the target says it is unhappy.

    Starts conservative on purpose. A scanner that opens at 50 rps is a
    scanner that gets its researcher banned, and the timing data it collects
    is worthless anyway once mitigation kicks in.
    """

    rps: float = 4.0
    burst: int = 4
    min_rps: float = 0.5
    jitter: float = 0.15

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()
        self._initial_rps = self.rps

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.burst, self._tokens + (now - self._last) * self.rps
                )
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    break
                await asyncio.sleep((1 - self._tokens) / max(self.rps, 0.01))
        if self.jitter:
            await asyncio.sleep(random.uniform(0, self.jitter))

    def back_off(self) -> None:
        """Halve throughput. Called on 429/503."""
        self.rps = max(self.min_rps, self.rps / 2)

    def recover(self) -> None:
        """Drift back up slowly after a clean stretch."""
        self.rps = min(self._initial_rps, self.rps * 1.1)


class PoliteClient:
    """Scope-aware, rate-limited wrapper around httpx.AsyncClient."""

    def __init__(
        self,
        scope: Scope,
        *,
        rps: float = 4.0,
        timeout: float = 15.0,
        user_agent: str = DEFAULT_UA,
        extra_headers: dict[str, str] | None = None,
        verify_tls: bool = True,
        follow_redirects: bool = False,
    ) -> None:
        self.scope = scope
        self.limiter = RateLimiter(rps=rps)
        self.request_count = 0
        self.blocked_count = 0
        self._consecutive_ok = 0
        headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if extra_headers:
            headers.update(extra_headers)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
            verify=verify_tls,
            follow_redirects=follow_redirects,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def __aenter__(self) -> "PoliteClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response | None:
        """Send one request. Returns None on network error or scope refusal."""
        try:
            self.scope.check(url)
        except ScopeError:
            self.blocked_count += 1
            return None

        await self.limiter.acquire()
        try:
            resp = await self._client.request(method, url, **kwargs)
        except (httpx.HTTPError, OSError):
            return None

        self.request_count += 1

        if resp.status_code in (429, 503):
            self.limiter.back_off()
            self._consecutive_ok = 0
        else:
            self._consecutive_ok += 1
            if self._consecutive_ok >= 20:
                self.limiter.recover()
                self._consecutive_ok = 0
        return resp

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)

    async def gather(self, coros: list, concurrency: int = 8) -> list:
        """Run coroutines with a concurrency cap, swallowing individual failures."""
        sem = asyncio.Semaphore(concurrency)

        async def _run(coro):
            async with sem:
                try:
                    return await coro
                except Exception:
                    return None

        return await asyncio.gather(*(_run(c) for c in coros))
