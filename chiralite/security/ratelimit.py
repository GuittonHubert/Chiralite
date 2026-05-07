"""Sliding-window rate limiter for per-CN and per-silo operation throttling.

Each key (typically a CN string or a ``"silo:<uuid>"`` compound key) maintains
an independent deque of hit timestamps.  Entries older than the window are
pruned on every check, so memory usage is bounded by ``limit`` entries per key.

Usage::

    limiter = RateLimiter(limit=100, window_s=1.0)

    # Returns False if this call would exceed 100 calls/second for the key.
    if not limiter.check("fm-macbook"):
        ...

    # Raises RateLimitExceeded immediately on excess.
    limiter.require("fm-macbook")
"""
from __future__ import annotations

import collections
import time

__all__ = ["RateLimitExceeded", "RateLimiter"]


class RateLimitExceeded(Exception):
    """Raised by ``RateLimiter.require`` when the rate limit is breached."""


class RateLimiter:
    """Sliding-window counter rate limiter.

    Args:
        limit:    Maximum number of allowed calls within *window_s* seconds.
        window_s: Duration of the sliding window in seconds.
    """

    def __init__(self, limit: int, window_s: float) -> None:
        if limit < 1:
            raise ValueError(f"limit must be ≥ 1, got {limit}")
        if window_s <= 0:
            raise ValueError(f"window_s must be > 0, got {window_s}")
        self._limit = limit
        self._window_s = window_s
        self._hits: dict[str, collections.deque[float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, key: str) -> bool:
        """Record a hit for *key* and return whether it is within the limit.

        The hit is only recorded if the call is allowed (i.e. this method
        returns ``True``).  Rejected calls are not counted so they cannot
        consume the remaining budget.

        Args:
            key: Arbitrary string key (e.g. client CN or silo UUID string).

        Returns:
            ``True`` if the call is allowed; ``False`` if the limit is exceeded.
        """
        now = time.monotonic()
        self._evict(key, now)
        hits = self._hits.setdefault(key, collections.deque())
        if len(hits) >= self._limit:
            return False
        hits.append(now)
        return True

    def require(self, key: str) -> None:
        """Like ``check``, but raises on excess instead of returning False.

        Raises:
            RateLimitExceeded: if *key* has exceeded the rate limit.
        """
        if not self.check(key):
            raise RateLimitExceeded(
                f"rate limit exceeded for {key!r} "
                f"({self._limit} calls / {self._window_s}s)"
            )

    def reset(self, key: str) -> None:
        """Clear all hit records for *key* (e.g. after a successful auth)."""
        self._hits.pop(key, None)

    def remaining(self, key: str) -> int:
        """Return how many more calls *key* may make in the current window."""
        now = time.monotonic()
        self._evict(key, now)
        used = len(self._hits.get(key, ()))
        return max(0, self._limit - used)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict(self, key: str, now: float) -> None:
        """Remove hits older than the sliding window for *key*."""
        cutoff = now - self._window_s
        hits = self._hits.get(key)
        if hits is None:
            return
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if not hits:
            del self._hits[key]
