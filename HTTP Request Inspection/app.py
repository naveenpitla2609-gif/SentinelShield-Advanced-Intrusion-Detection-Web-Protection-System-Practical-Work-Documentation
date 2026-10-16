
import logging

from flask import Flask, jsonify, request, g
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "HTTP Request Inspection"))
sys.path.insert(0, str(BASE_DIR / "Attack Signature Identification"))
sys.path.insert(0, str(BASE_DIR / "Behavior Monitoring and Rate Limiting"))
sys.path.insert(0, str(BASE_DIR / "Log Analysis"))
sys.path.insert(0, str(BASE_DIR / "Dashboard Interpretation"))
from dashboard_routes import dashboard_bp

from request_inspector import inspect_request
from event_logger import log_event
from rate_limiter import RateLimiter
from activity_monitor import ActivityMonitor


app = Flask(__name__, template_folder=str(BASE_DIR / "Dashboard Interpretation"))
app.register_blueprint(dashboard_bp)

app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.config["RATE_LIMIT_REQUESTS"] = 30
app.config["RATE_LIMIT_WINDOW_SECONDS"] = 60
app.config["ACTIVITY_THRESHOLD"] = 10
app.config["ACTIVITY_WINDOW_SECONDS"] = 60

rate_limiter = RateLimiter(
    max_requests=app.config["RATE_LIMIT_REQUESTS"],
    window_seconds=app.config["RATE_LIMIT_WINDOW_SECONDS"],
)

activity_monitor = ActivityMonitor(
    max_events=app.config["ACTIVITY_THRESHOLD"],
    window_seconds=app.config["ACTIVITY_WINDOW_SECONDS"],
)


class ColorFormatter(logging.Formatter):
    RESET = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"

    def format(self, record):
        message = super().format(record)
        if record.levelno >= logging.ERROR:
            color = self.RED
        elif record.levelno >= logging.WARNING:
            color = self.YELLOW
        else:
            color = self.GREEN
        return f"{color}{self.BOLD}{message}{self.RESET}"


console_logger = logging.getLogger("sentinelshield.console")
console_logger.setLevel(logging.INFO)
console_logger.propagate = False

if not console_logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        ColorFormatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    console_logger.addHandler(console_handler)


@app.before_request
def apply_security_checks():
    if request.endpoint == "health":
        return None

    client_ip = request.remote_addr or "unknown"

    ignored_activity_paths = {
        "/", "/dashboard", "/api/dashboard-stats",
        "/attack-monitoring", "/event-logs",
        "/protection-history", "/health",
    }

    endpoint = request.endpoint or ""
    is_dashboard_endpoint = (
        endpoint.startswith("dashboard.") or endpoint == "static"
    )

    if (
        request.path not in ignored_activity_paths
        and not is_dashboard_endpoint
    ):
        activity = activity_monitor.record(client_ip)

        if activity["suspicious"]:
            console_logger.warning(
                "SUSPICIOUS ACTIVITY | IP=%s | COUNT=%s | WINDOW=%ss",
                client_ip,
                activity["event_count"],
                activity["window_seconds"],
            )
            log_event(
                {
                    "method": request.method,
                    "path": request.path,
                    "detections": [{"category": "REPEATED_REQUESTS"}],
                },
                client_ip,
                "SUSPICIOUS_ACTIVITY",
            )

    result = rate_limiter.check(client_ip)
    g.rate_limit_result = result

    if not result["allowed"]:
        response = jsonify({
            "project": "SentinelShield",
            "status": "rate_limited",
            "error": "Too Many Requests",
            "message": "Request limit exceeded. Please retry later.",
            "limit": result["limit"],
            "remaining": result["remaining"],
            "retry_after": result["retry_after"],
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(result["retry_after"])
        return response

    return None


@app.after_request
def add_security_headers(response):
    result = getattr(g, "rate_limit_result", None)

    if result is not None:
        response.headers["X-RateLimit-Limit"] = str(result["limit"])
        response.headers["X-RateLimit-Remaining"] = str(
            result["remaining"]
        )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return jsonify({
        "application": "SentinelShield",
        "status": "running",
        "version": "0.1.0",
    }), 200


@app.route(
    "/inspect",
    methods=[
        "GET", "POST", "PUT", "PATCH", "DELETE",
        "TRACE", "CONNECT", "BREW",
    ],
)
def inspect():
    result = inspect_request()
    source_ip = request.remote_addr or "unknown"
    is_malicious = result.get("is_malicious", False)

    if is_malicious:
        event = log_event(result, source_ip, "BLOCKED")
        console_logger.error(
            "ATTACK BLOCKED | IP=%s | METHOD=%s | PATH=%s",
            source_ip, request.method, request.path,
        )
        return jsonify({
            "project": "SentinelShield",
            "status": "blocked",
            "is_malicious": True,
            "reason": "Suspicious request detected",
            "method": result["method"],
            "path": result["path"],
            "component_results": result.get("component_results", {}),
            "detections": result.get("detections", []),
            "event": event,
        }), 403

    event = log_event(result, source_ip, "ALLOWED")
    console_logger.info(
        "REQUEST ALLOWED | IP=%s | METHOD=%s | PATH=%s",
        source_ip, request.method, request.path,
    )
    return jsonify({
        "project": "SentinelShield",
        "status": "allowed",
        "is_malicious": False,
        "message": "No configured attack signature matched",
        "method": result["method"],
        "path": result["path"],
        "component_results": result.get("component_results", {}),
        "detections": result.get("detections", []),
        "event": event,
    }), 200


def print_startup_banner():
    reset = "\033[0m"
    cyan = "\033[96m"
    green = "\033[92m"
    bold = "\033[1m"

    print()
    print(cyan + bold + "=" * 62 + reset)
    print(cyan + bold + "          SENTINELSHIELD SECURITY SYSTEM" + reset)
    print(cyan + "             PROTECTION & MONITORING" + reset)
    print(cyan + bold + "=" * 62 + reset)
    print(green + "[+] Rate Limiter        : ENABLED" + reset)
    print(green + "[+] Attack Detection    : ENABLED" + reset)
    print(green + "[+] Security Event Log  : ENABLED" + reset)
    print(green + "[+] Activity Monitor    : ENABLED" + reset)
    print(
        cyan + "[+] Activity Threshold  : "
        + str(app.config["ACTIVITY_THRESHOLD"])
        + " requests / "
        + str(app.config["ACTIVITY_WINDOW_SECONDS"])
        + " seconds" + reset
    )
    print(cyan + "[+] Health Endpoint     : /health" + reset)
    print(cyan + "[+] Inspection Endpoint : /inspect" + reset)
    print(cyan + "[+] Local Server        : http://127.0.0.1:5000" + reset)
    print(cyan + bold + "=" * 62 + reset)
    print()


if __name__ == "__main__":
    print_startup_banner()
    app.run(host="127.0.0.1", port=5000, debug=False)





