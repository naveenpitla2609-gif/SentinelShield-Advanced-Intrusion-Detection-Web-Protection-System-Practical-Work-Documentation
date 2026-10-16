from rate_limiter import RateLimiter
from activity_monitor import ActivityMonitor
from app import app


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(max_requests=2, window_seconds=60)

    assert limiter.check("test-ip")["allowed"] is True
    assert limiter.check("test-ip")["allowed"] is True

    result = limiter.check("test-ip")
    assert result["allowed"] is False
    assert result["remaining"] == 0


def test_activity_monitor_detects_repeated_requests():
    monitor = ActivityMonitor(max_events=2, window_seconds=60)

    assert monitor.record("test-ip")["suspicious"] is False
    assert monitor.record("test-ip")["suspicious"] is False

    result = monitor.record("test-ip")
    assert result["suspicious"] is True
    assert result["event_count"] == 3


def test_health_response_has_security_headers():
    client = app.test_client()
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
from event_logger import log_event, LOG_FILE


def test_security_event_is_written_to_log():
    result = {
        "method": "GET",
        "path": "/test-event",
        "detections": [],
    }

    event = log_event(result, "192.0.2.50", "TEST_EVENT")

    assert event["source_ip"] == "192.0.2.50"
    assert event["action"] == "TEST_EVENT"
    assert LOG_FILE.exists()

    with LOG_FILE.open("r", encoding="utf-8") as file:
        assert "TEST_EVENT" in file.read()

