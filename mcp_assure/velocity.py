"""Sliding-window velocity ceilings."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class VelocityLimit:
    max_events: int
    window_seconds: float


DEFAULT_LIMITS: dict[str, VelocityLimit] = {
    "per_identity": VelocityLimit(60, 60.0),
    "per_actor": VelocityLimit(200, 60.0),
    "global": VelocityLimit(500, 60.0),
}


class VelocityTracker:
    def __init__(self, limits: dict[str, VelocityLimit] | None = None) -> None:
        self.limits = dict(limits or DEFAULT_LIMITS)
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, q: deque[float], window: float, now: float) -> None:
        while q and (now - q[0]) > window:
            q.popleft()

    def check_and_record(
        self,
        *,
        identity_key: str,
        actor: str,
        now: float | None = None,
    ) -> tuple[bool, str]:
        now = time.time() if now is None else now
        with self._lock:
            checks = [
                (f"id:{identity_key}", self.limits["per_identity"]),
                (f"actor:{actor}", self.limits["per_actor"]),
                ("global", self.limits["global"]),
            ]
            for key, lim in checks:
                q = self._buckets[key]
                self._prune(q, lim.window_seconds, now)
                if len(q) >= lim.max_events:
                    return (
                        False,
                        f"velocity exceeded for {key}: "
                        f"{len(q)}/{lim.max_events} in {lim.window_seconds}s",
                    )
            for key, _lim in checks:
                self._buckets[key].append(now)
            return True, "ok"
