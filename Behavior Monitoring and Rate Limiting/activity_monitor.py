
from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class ActivityMonitor:
    """Track repeated activity from each client IP."""

    def __init__(self, max_events=10, window_seconds=60):
        if max_events < 1:
            raise ValueError("max_events must be at least 1")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)
        self._lock = Lock()

    def record(self, client_ip):
        now = monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            events = self._events[client_ip]

            while events and events[0] <= cutoff:
                events.popleft()

            events.append(now)

            count = len(events)
            suspicious = count > self.max_events

            return {
                "client_ip": client_ip,
                "event_count": count,
                "threshold": self.max_events,
                "window_seconds": self.window_seconds,
                "suspicious": suspicious,
                "status": (
                    "SUSPICIOUS"
                    if suspicious
                    else "NORMAL"
                ),
            }
