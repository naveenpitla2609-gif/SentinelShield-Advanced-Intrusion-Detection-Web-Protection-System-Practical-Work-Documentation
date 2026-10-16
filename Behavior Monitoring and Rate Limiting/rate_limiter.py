
from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class RateLimiter:
    """Thread-safe, in-memory sliding-window rate limiter."""

    def __init__(self, max_requests=30, window_seconds=60):
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = defaultdict(deque)
        self._lock = Lock()

    def check(self, client_ip):
        now = monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._requests[client_ip]

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                retry_after = max(
                    1,
                    int(
                        timestamps[0]
                        + self.window_seconds
                        - now
                    ) + 1,
                )

                return {
                    "allowed": False,
                    "limit": self.max_requests,
                    "remaining": 0,
                    "retry_after": retry_after,
                }

            timestamps.append(now)

            return {
                "allowed": True,
                "limit": self.max_requests,
                "remaining": self.max_requests - len(timestamps),
                "retry_after": 0,
            }
