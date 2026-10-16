
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, render_template

dashboard_bp = Blueprint("dashboard", __name__)

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "Log Analysis" / "security_events.jsonl"


def read_security_events():
    events = []

    if not LOG_FILE.exists():
        return events

    try:
        with LOG_FILE.open("r", encoding="utf-8-sig") as file:
            for line in file:
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        events.append(event)
                except (json.JSONDecodeError, TypeError):
                    continue
    except OSError:
        return []

    return events


def event_action(event):
    return str(event.get("action", "UNKNOWN")).upper()


@dashboard_bp.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@dashboard_bp.get("/api/dashboard-stats")
def dashboard_stats():
    events = read_security_events()

    actions = Counter(event_action(event) for event in events)

    high_severity = sum(
        str(event.get("severity", "")).upper() == "HIGH"
        for event in events
    )

    now = datetime.now(timezone.utc)
    bucket_seconds = 300
    current_bucket = int(now.timestamp()) // bucket_seconds
    buckets = []

    for offset in range(11, -1, -1):
        bucket_id = current_bucket - offset

        buckets.append({
            "bucket": bucket_id,
            "label": datetime.fromtimestamp(
                bucket_id * bucket_seconds,
                timezone.utc,
            ).astimezone().strftime("%H:%M"),
            "total": 0,
            "blocked": 0,
        })

    lookup = {item["bucket"]: item for item in buckets}

    for event in events:
        try:
            timestamp = event.get("timestamp")

            if not isinstance(timestamp, str):
                continue

            parsed = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            bucket = lookup.get(
                int(parsed.timestamp()) // bucket_seconds
            )

            if bucket:
                bucket["total"] += 1

                if event_action(event) == "BLOCKED":
                    bucket["blocked"] += 1

        except (TypeError, ValueError, OverflowError, OSError):
            continue

    response = jsonify({
        "stats": {
            "total": len(events),
            "blocked": actions.get("BLOCKED", 0),
            "allowed": actions.get("ALLOWED", 0),
            "high_severity": high_severity,
            "actions": dict(actions),
        },
        "activity": [
            {
                "label": item["label"],
                "total": item["total"],
                "blocked": item["blocked"],
            }
            for item in buckets
        ],
        "events": list(reversed(events[-100:])),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })

    response.headers["Cache-Control"] = "no-store"
    return response


# ============================================================
# ATTACK MONITORING
# Show requests that were actually blocked by detection.
# Repeated-activity alerts remain available in Event Logs.
# ============================================================

@dashboard_bp.get("/attack-monitoring")
def attack_monitoring():
    events = read_security_events()

    attacks = [
        event
        for event in events
        if event_action(event) == "BLOCKED"
    ]

    return render_template(
        "section.html",
        page_title="Attack Monitoring",
        page_subtitle="Requests blocked by attack detection",
        active_page="attacks",
        events=list(reversed(attacks[-200:])),
        total=len(attacks),
    )


# ============================================================
# EVENT LOGS
# Show every recorded event, including suspicious activity.
# ============================================================

@dashboard_bp.get("/event-logs")
def event_logs():
    events = read_security_events()

    return render_template(
        "section.html",
        page_title="Event Logs",
        page_subtitle="Complete record of all security events",
        active_page="logs",
        events=list(reversed(events[-200:])),
        total=len(events),
    )


# ============================================================
# PROTECTION HISTORY
# Show recorded allow, block and rate-limit actions.
# ============================================================

@dashboard_bp.get("/protection-history")
def protection_history():
    events = read_security_events()

    protection_actions = {
        "BLOCKED",
        "ALLOWED",
        "RATE_LIMITED",
    }

    history = [
        event
        for event in events
        if event_action(event) in protection_actions
    ]

    return render_template(
        "section.html",
        page_title="Protection History",
        page_subtitle="Recorded allow, block, and rate-limit actions",
        active_page="protection",
        events=list(reversed(history[-200:])),
        total=len(history),
    )

