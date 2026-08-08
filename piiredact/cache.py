"""Bounded content-hash cache.

The provider payload is re-scanned before *every* API call, so the same
conversation history passes through the redactor dozens of times per turn.
Hashing a string and hitting a dict is ~1000x cheaper than re-running the rule
set over it, and it is what keeps the steady-state cost of the last-mile guard
inside the latency budget.

Entries are keyed on ``(vault_generation, sha256(text))``: learning a new
value bumps the generation and retires every stale entry at once, so a value
discovered mid-session can never be served from a cache that predates it.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Generic, Optional, Tuple, TypeVar

T = TypeVar("T")


class LruCache(Generic[T]):
    """Small thread-safe LRU. ``maxsize <= 0`` disables caching entirely."""

    def __init__(self, maxsize: int = 4096) -> None:
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._data: "OrderedDict[Tuple[int, str], T]" = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, generation: int, digest: str) -> Optional[T]:
        if self._maxsize <= 0:
            return None
        key = (generation, digest)
        with self._lock:
            value = self._data.get(key)
            if value is None:
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def put(self, generation: int, digest: str, value: T) -> None:
        if self._maxsize <= 0:
            return
        key = (generation, digest)
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        return len(self._data)
