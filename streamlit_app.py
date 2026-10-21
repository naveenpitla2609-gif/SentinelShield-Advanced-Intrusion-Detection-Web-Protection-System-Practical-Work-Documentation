
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

# ============================================================
# SENTINELSHIELD - STREAMLIT SECURITY DASHBOARD
# Existing Flask security engine remains unchanged.
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "Log Analysis" / "security_events.jsonl"

st.set_page_config(
    page_title="SentinelShield | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


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


def action_of(event):
    return str(event.get("action", "UNKNOWN")).upper()


def severity_of(event):
    return str(event.get("severity", "UNKNOWN")).upper()


def format_timestamp(value):
    if not isinstance(value, str):
        return "Unknown"

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
        return timestamp.astimezone().strftime(
            "%d %b %Y, %H:%M:%S"
        )
    except (ValueError, TypeError, OverflowError):
        return value


# -------------------- PAGE STYLING --------------------

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background-color: #111827;
    }

    div[data-testid="stMetric"] {
        background: #151f32;
        border: 1px solid #26354c;
        padding: 18px;
        border-radius: 12px;
    }

    div[data-testid="stMetricLabel"] {
        color: #aab8cc;
    }

    h1, h2, h3 {
        color: #f3f6fc;
    }

    .security-subtitle {
        color: #9caec5;
        font-size: 15px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------- SIDEBAR --------------------

st.sidebar.title("🛡️ SentinelShield")
st.sidebar.caption("Advanced Intrusion Detection")
st.sidebar.divider()

page = st.sidebar.radio(
    "Security Center",
    [
        "Overview",
        "Attack Monitoring",
        "Event Logs",
        "Protection History",
    ],
)

if st.sidebar.button("Refresh Dashboard", use_container_width=True):
    st.rerun()

st.sidebar.divider()
st.sidebar.caption("Security Monitoring Console")

# -------------------- LOAD EVENTS --------------------

events = read_security_events()
actions = Counter(action_of(event) for event in events)

blocked_events = [
    event for event in events
    if action_of(event) == "BLOCKED"
]

rate_limited_events = [
    event for event in events
    if action_of(event) in {"RATE_LIMITED", "RATE LIMITED"}
]

high_events = [
    event for event in events
    if severity_of(event) == "HIGH"
]

# -------------------- HEADER --------------------

st.title("🛡️ SentinelShield Security Center")
st.markdown(
    '<p class="security-subtitle">'
    'Intrusion detection, protection monitoring and security event analysis'
    '</p>',
    unsafe_allow_html=True,
)

st.caption(
    f"Last dashboard refresh: "
    f"{datetime.now().astimezone().strftime('%d %b %Y, %H:%M:%S')}"
)

if not LOG_FILE.exists():
    st.info(
        "No security log file found yet. "
        "The dashboard will display recorded events when the log file exists."
    )

# -------------------- OVERVIEW --------------------

if page == "Overview":
    st.subheader("Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", len(events))
    col2.metric("Blocked Requests", len(blocked_events))
    col3.metric("High Severity", len(high_events))
    col4.metric("Rate-Limit Events", len(rate_limited_events))

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Event Action Distribution")

        if actions:
            chart_data = {
                action: count
                for action, count in actions.items()
            }
            st.bar_chart(chart_data)
        else:
            st.info("No security events recorded yet.")

    with right:
        st.subheader("Severity Distribution")

        severity_counts = Counter(
            severity_of(event) for event in events
        )

        if severity_counts:
            st.bar_chart(dict(severity_counts))
        else:
            st.info("No severity data available yet.")

    st.subheader("Recent Security Events")

    if events:
        recent = list(reversed(events[-10:]))

        for event in recent:
            action = action_of(event)
            severity = severity_of(event)

            if action == "BLOCKED":
                status = "🔴 BLOCKED"
            elif action in {"RATE_LIMITED", "RATE LIMITED"}:
                status = "🟠 RATE LIMITED"
            elif action == "ALLOWED":
                status = "🟢 ALLOWED"
            else:
                status = f"⚪ {action}"

            st.markdown(
                f"**{status}** · "
                f"Severity: `{severity}` · "
                f"Path: `{event.get('path', 'Unknown')}`"
            )

            st.caption(
                f"{format_timestamp(event.get('timestamp'))} | "
                f"IP: {event.get('source_ip', 'Unknown')}"
            )
    else:
        st.info("Waiting for security events.")

# -------------------- ATTACK MONITORING --------------------

elif page == "Attack Monitoring":
    st.subheader("🚨 Attack Monitoring")
    st.caption("Requests recorded with the BLOCKED action.")

    st.metric("Blocked Requests", len(blocked_events))

    if blocked_events:
        st.dataframe(
            [
                {
                    "Timestamp": format_timestamp(
                        event.get("timestamp")
                    ),
                    "Source IP": event.get("source_ip", "Unknown"),
                    "Method": event.get("method", "Unknown"),
                    "Path": event.get("path", "Unknown"),
                    "Categories": ", ".join(
                        event.get("categories", [])
                    ) if isinstance(event.get("categories"), list)
                    else str(event.get("categories", "")),
                    "Severity": severity_of(event),
                    "Action": action_of(event),
                }
                for event in reversed(blocked_events[-200:])
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No blocked requests are present in the current log.")

# -------------------- EVENT LOGS --------------------

elif page == "Event Logs":
    st.subheader("📋 Security Event Logs")

    if events:
        st.dataframe(
            [
                {
                    "Timestamp": format_timestamp(
                        event.get("timestamp")
                    ),
                    "Source IP": event.get("source_ip", "Unknown"),
                    "Method": event.get("method", "Unknown"),
                    "Path": event.get("path", "Unknown"),
                    "Categories": ", ".join(
                        event.get("categories", [])
                    ) if isinstance(event.get("categories"), list)
                    else str(event.get("categories", "")),
                    "Severity": severity_of(event),
                    "Action": action_of(event),
                }
                for event in reversed(events[-500:])
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No security events available.")

# -------------------- PROTECTION HISTORY --------------------

elif page == "Protection History":
    st.subheader("🔐 Protection History")

    protection_actions = {
        "BLOCKED",
        "ALLOWED",
        "RATE_LIMITED",
        "RATE LIMITED",
    }

    history = [
        event for event in events
        if action_of(event) in protection_actions
    ]

    st.metric("Recorded Protection Actions", len(history))

    if history:
        st.dataframe(
            [
                {
                    "Timestamp": format_timestamp(
                        event.get("timestamp")
                    ),
                    "Action": action_of(event),
                    "Severity": severity_of(event),
                    "Path": event.get("path", "Unknown"),
                    "Source IP": event.get("source_ip", "Unknown"),
                }
                for event in reversed(history[-200:])
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No protection actions recorded yet.")

st.divider()
st.caption(
    "SentinelShield | Security Monitoring Dashboard | "
    "Existing Flask detection engine preserved"
)