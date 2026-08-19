"""Fail-closed per-identity rate and bulk-abuse controls."""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque


class AnomalyLimiter:
    def __init__(self) -> None:
        self.window_seconds = int(os.getenv("NEXUS_RATE_WINDOW_SECONDS", "60"))
        self.limit = int(os.getenv("NEXUS_RATE_LIMIT_PER_MINUTE", "30"))
        self.burst = int(os.getenv("NEXUS_BURST_LIMIT", "8"))
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, identity: str) -> None:
        now = time.monotonic()
        events = self._events[identity]
        while events and now - events[0] > self.window_seconds:
            events.popleft()
        if len(events) >= self.limit:
            raise PermissionError("rate limit exceeded")
        recent = sum(1 for t in events if now - t <= 10)
        if recent >= self.burst:
            raise PermissionError("anomalous burst detected")
        events.append(now)
