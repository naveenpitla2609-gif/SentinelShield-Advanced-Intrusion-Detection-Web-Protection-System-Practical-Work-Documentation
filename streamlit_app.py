from pathlib import Path
from collections import Counter
from html import escape
import json
import streamlit as st

# ============================================================
# SENTINELSHIELD | APPLE LIQUID GLASS SECURITY OPERATIONS CENTER
# ============================================================

st.set_page_config(
    page_title="SentinelShield | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path(__file__).resolve().parent


# ============================================================
# SECURITY EVENT LOG
# ============================================================

def find_event_log():
    candidates = [
        BASE_DIR / "Log Analysis" / "security_events.jsonl",
        BASE_DIR / "Log Analysis" / "logs" / "security_events.jsonl",
        BASE_DIR / "logs" / "security_events.jsonl",
        BASE_DIR / "logging_system" / "security_events.jsonl",
        BASE_DIR / "security_events.jsonl",
    ]

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    try:
        return next(BASE_DIR.rglob("security_events.jsonl"), None)
    except OSError:
        return None


LOG_FILE = find_event_log()


def safe_value(value, default="Unknown"):
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip()


def normalize_event(data, index):
    categories = data.get(
        "categories",
        data.get("attack_types", data.get("detections", [])),
    )

    if isinstance(categories, str):
        categories = [categories]

    if not isinstance(categories, list):
        categories = []

    attack_name = (
        data.get("attack_name")
        or data.get("attack")
        or data.get("signature")
        or data.get("category")
    )

    if not attack_name and categories:
        attack_name = ", ".join(map(str, categories))

    if not attack_name:
        attack_name = (
            "Suspicious Activity"
            if data.get("is_malicious")
            else "Security Event"
        )

    timestamp = safe_value(
        data.get("timestamp", data.get("time")),
        "Timestamp unavailable",
    )

    source_ip = safe_value(
        data.get(
            "source_ip",
            data.get("ip", data.get("client_ip", data.get("remote_addr"))),
        )
    )

    method = safe_value(
        data.get("method", data.get("request_method")),
        "—",
    ).upper()

    path = safe_value(
        data.get("path", data.get("url", data.get("request_path"))),
        "—",
    )

    severity = safe_value(data.get("severity"), "MEDIUM").upper()

    action = safe_value(
        data.get("action", data.get("status")),
        "DETECTED",
    ).upper()

    event_id = json.dumps(
        [timestamp, source_ip, method, path, attack_name, action],
        ensure_ascii=False,
    )

    return {
        "id": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "method": method,
        "path": path,
        "attack_name": safe_value(attack_name),
        "severity": severity,
        "action": action,
        "categories": categories,
        "details": data,
        "index": index,
    }


def load_events():
    if not LOG_FILE:
        return []

    events = []

    try:
        with LOG_FILE.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            for index, line in enumerate(file, start=1):
                try:
                    data = json.loads(line.strip())
                except (json.JSONDecodeError, ValueError):
                    continue

                if isinstance(data, dict):
                    events.append(normalize_event(data, index))

    except OSError:
        return []

    return list(reversed(events))


EVENTS = load_events()


# ============================================================
# ATTACK IDENTIFICATION AND ANALYTICS
# ============================================================

ATTACK_TERMS = (
    "sql injection",
    "sql_injection",
    "sqli",
    "xss",
    "cross-site scripting",
    "path traversal",
    "path_traversal",
    "command injection",
    "command_injection",
    "brute force",
    "brute_force",
    "rate limit exceeded",
    "rate_limited",
    "rate_limit",
    "directory traversal",
    "malicious",
    "blocked",
    "suspicious",
)


def is_attack(event):
    searchable = " ".join([
        event["attack_name"],
        " ".join(map(str, event["categories"])),
        event["action"],
    ]).lower()

    return any(term in searchable for term in ATTACK_TERMS)


ATTACK_EVENTS = [event for event in EVENTS if is_attack(event)]

RATE_LIMIT_EVENTS = [
    event for event in EVENTS
    if (
        "RATE_LIMIT" in event["action"]
        or "RATE_LIMIT" in event["attack_name"].upper()
        or "429" in event["action"]
        or "TOO MANY" in event["attack_name"].upper()
        or "RATE_LIMIT" in " ".join(
            map(str, event["categories"])
        ).upper()
    )
]

IP_COUNTS = Counter(
    event["source_ip"]
    for event in EVENTS
    if event["source_ip"] not in ("Unknown", "—")
)

SEVERITY_COUNTS = Counter(event["severity"] for event in EVENTS)
ACTION_COUNTS = Counter(event["action"] for event in EVENTS)
METHOD_COUNTS = Counter(
    event["method"] for event in EVENTS
    if event["method"] != "—"
)

if "read_alerts" not in st.session_state:
    st.session_state.read_alerts = set()

if "show_alert_panel" not in st.session_state:
    st.session_state.show_alert_panel = False

if "open_alert_center" not in st.session_state:
    st.session_state.open_alert_center = False

UNREAD_ALERTS = [
    event for event in ATTACK_EVENTS
    if event["id"] not in st.session_state.read_alerts
]


# ============================================================
# APPLE LIQUID GLASS DESIGN SYSTEM
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

:root {
    --ink: #172b49;
    --muted: #637894;
    --blue: #3478f6;
    --cyan: #20b9d7;
    --purple: #8871f8;
    --line: rgba(255,255,255,.78);
    --glass: rgba(255,255,255,.66);
}

html, body, [class*="css"] {
    font-family: Inter, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
}

.stApp {
    color: var(--ink);
    background:
        radial-gradient(ellipse at 5% 0%,
            rgba(92,191,255,.38), transparent 32%),
        radial-gradient(ellipse at 96% 8%,
            rgba(184,160,255,.34), transparent 31%),
        radial-gradient(ellipse at 48% 100%,
            rgba(120,221,230,.22), transparent 37%),
        linear-gradient(135deg,#eaf4ff 0%,#f4f1ff 48%,#e7f8fb 100%);
    background-attachment: fixed;
}

[data-testid="stHeader"] {
    background: rgba(239,247,255,.35);
}

[data-testid="stAppViewContainer"] {
    background: transparent;
}

[data-testid="stSidebar"] {
    background:
        linear-gradient(160deg,
            rgba(255,255,255,.80),
            rgba(232,242,255,.68));
    border-right: 1px solid rgba(255,255,255,.95);
    box-shadow: 12px 0 36px rgba(71,105,159,.10);
    backdrop-filter: blur(28px) saturate(160%);
    -webkit-backdrop-filter: blur(28px) saturate(160%);
}

[data-testid="stSidebar"] * {
    color: #203958;
}

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
    color: #60748f;
}

.block-container {
    max-width: 1700px;
    padding-top: 1.15rem !important;
    padding-bottom: 2rem;
    padding-left: 1.8rem;
    padding-right: 1.8rem;
}

h1, h2, h3, p, label {
    color: var(--ink);
}

h1, h2, h3 {
    letter-spacing: -.035em;
}

/* HERO */

.hero {
    position: relative;
    isolation: isolate;
    overflow: hidden;
    min-height: 184px;
    padding: 29px 31px;
    border-radius: 30px;
    margin-bottom: 18px;
    background:
        radial-gradient(circle at 88% 10%,
            rgba(255,255,255,.65), transparent 27%),
        radial-gradient(circle at 78% 115%,
            rgba(99,210,255,.35), transparent 38%),
        linear-gradient(120deg,
            rgba(255,255,255,.89),
            rgba(221,237,255,.69) 48%,
            rgba(231,225,255,.76));
    border: 1px solid rgba(255,255,255,.96);
    box-shadow:
        0 22px 55px rgba(73,104,158,.13),
        inset 0 1px 0 rgba(255,255,255,.98),
        inset 0 -1px 0 rgba(255,255,255,.42);
    backdrop-filter: blur(28px) saturate(165%);
    -webkit-backdrop-filter: blur(28px) saturate(165%);
}

.hero:after {
    content: "";
    position: absolute;
    z-index: -1;
    width: 250px;
    height: 250px;
    right: -60px;
    top: -100px;
    border-radius: 50%;
    background: rgba(107,158,255,.13);
    filter: blur(8px);
}

.hero-kicker {
    color: #3973c5;
    font-size: .68rem;
    font-weight: 900;
    letter-spacing: .17em;
}

.hero-title {
    color: #173254;
    font-size: clamp(2rem,3.5vw,2.8rem);
    font-weight: 900;
    letter-spacing: -.06em;
    margin: 8px 0;
}

.hero-subtitle {
    color: #617792;
    font-size: .91rem;
    line-height: 1.55;
}
.hero-status {
    display: inline-block;
    color: #147d5a;
    background: rgba(53,204,143,.12);
    border: 1px solid rgba(53,175,126,.28);
    border-radius: 22px;
    padding: 7px 12px;
    margin-top: 12px;
    font-size: .65rem;
    font-weight: 900;
    letter-spacing: .07em;
}

/* LIQUID GLASS SURFACES */

.metric-card, .module-card, .panel, .attack-card, .mini-card {
    position: relative;
    isolation: isolate;
    overflow: hidden;
    background:
        linear-gradient(145deg,
            rgba(255,255,255,.87),
            rgba(255,255,255,.53));
    border: 1px solid rgba(255,255,255,.96);
    box-shadow:
        0 12px 32px rgba(67,103,158,.09),
        inset 0 1px 0 rgba(255,255,255,.98),
        inset 0 -1px 0 rgba(190,212,242,.23);
    backdrop-filter: blur(24px) saturate(160%);
    -webkit-backdrop-filter: blur(24px) saturate(160%);
    transition: transform .2s ease,
        border-color .2s ease, box-shadow .2s ease;
}

.metric-card:hover, .module-card:hover, .panel:hover,
.attack-card:hover, .mini-card:hover {
    transform: translateY(-3px);
    border-color: rgba(116,173,255,.68);
    box-shadow:
        0 18px 38px rgba(67,103,158,.15),
        inset 0 1px 0 rgba(255,255,255,1);
}

.metric-card {
    min-height: 142px;
    padding: 20px;
    margin-bottom: 13px;
    border-radius: 23px;
    border-left: 3px solid var(--accent);
}

.metric-label {
    color: #617691;
    font-size: .68rem;
    font-weight: 850;
    text-transform: uppercase;
    letter-spacing: .08em;
}

.metric-value {
    color: #183453;
    font-size: 1.9rem;
    font-weight: 900;
    letter-spacing: -.055em;
    margin: 11px 0 6px;
    overflow-wrap: anywhere;
}

.metric-caption {
    color: #71839b;
    font-size: .73rem;
    line-height: 1.5;
}

/* SECTION HEADER */

.section-header {
    display: flex;
    gap: 14px;
    align-items: center;
    margin: 8px 0 19px;
    padding: 18px 21px;
    border-radius: 22px;
    background:
        linear-gradient(120deg,
            rgba(255,255,255,.88),
            rgba(238,245,255,.63));
    border: 1px solid rgba(255,255,255,.96);
    box-shadow:
        0 12px 30px rgba(67,103,158,.08),
        inset 0 1px 0 white;
    backdrop-filter: blur(22px) saturate(150%);
    -webkit-backdrop-filter: blur(22px) saturate(150%);
}

.section-icon {font-size: 1.8rem;}

.section-title {
    color: #1b3657;
    font-size: 1.3rem;
    font-weight: 900;
    letter-spacing: -.035em;
}

.section-description {
    color: #6c809b;
    font-size: .78rem;
    line-height: 1.55;
    margin-top: 4px;
}

/* MODULE CARDS */

.module-card {
    min-height: 147px;
    padding: 19px;
    border-radius: 22px;
    margin-bottom: 14px;
}

.module-icon {font-size: 1.65rem;}

.module-title {
    color: #203958;
    font-weight: 850;
    font-size: .94rem;
    line-height: 1.45;
    margin-top: 10px;
}

.module-description {
    color: #6b809b;
    font-size: .77rem;
    line-height: 1.65;
    margin-top: 7px;
}

.pill {
    float: right;
    font-size: .58rem;
    color: #197b5a;
    border: 1px solid rgba(60,181,130,.24);
    background: rgba(72,199,146,.12);
    border-radius: 20px;
    padding: 4px 8px;
    font-weight: 900;
    letter-spacing: .04em;
}

/* PANELS */

.panel {
    padding: 18px;
    border-radius: 22px;
    margin-bottom: 15px;
}

.panel-title {
    font-size: .91rem;
    font-weight: 900;
    color: #203958;
    margin-bottom: 5px;
}

.panel-subtitle {
    font-size: .73rem;
    color: #7487a0;
    line-height: 1.55;
    margin-bottom: 12px;
}

/* COMPACT FREQUENCY BARS */

.bar-row {
    display: grid;
    grid-template-columns: minmax(100px,1.2fr) minmax(70px,2fr) 38px;
    gap: 10px;
    align-items: center;
    margin: 12px 0;
}

.bar-label {
    font-size: .73rem;
    color: #3f5774;
    overflow-wrap: anywhere;
}

.bar-track {
    height: 9px;
    background: rgba(104,139,185,.12);
    border: 1px solid rgba(151,179,215,.18);
    border-radius: 20px;
    overflow: hidden;
}

.bar-fill {
    height: 100%;
    border-radius: 20px;
    background: linear-gradient(90deg,#5a8cf6,#53d1dc);
    box-shadow: 0 0 12px rgba(78,149,246,.18);
}

.bar-count {
    font-size: .75rem;
    text-align: right;
    color: #203958;
    font-weight: 900;
}

/* EVENT TABLE */

.table-head {
    color: #7a8da5;
    font-size: .65rem;
    font-weight: 900;
    text-transform: uppercase;
    padding: 9px 4px;
    letter-spacing: .035em;
}

.table-cell {
    color: #354c69;
    font-size: .72rem;
    padding: 10px 4px;
    overflow-wrap: anywhere;
    border-top: 1px solid rgba(137,163,198,.18);
}

.ip {
    color: #167da5;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-weight: 700;
}

.severity {
    display: inline-block;
    font-size: .60rem;
    font-weight: 900;
    border-radius: 8px;
    padding: 4px 7px;
    letter-spacing: .035em;
}

.red {
    color:#bf3048;
    background:rgba(255,91,113,.12);
    border:1px solid rgba(223,68,91,.22);
}
.amber {
    color:#97600b;
    background:rgba(247,183,63,.15);
    border:1px solid rgba(213,151,31,.23);
}
.green {
    color:#167d56;
    background:rgba(50,192,126,.12);
    border:1px solid rgba(62,177,126,.23);
}

/* ATTACK CARDS */

.attack-card {
    padding: 16px 18px;
    margin-bottom: 10px;
    border-radius: 19px;
    border-left: 3px solid var(--attack-accent);
}

.attack-name {
    font-size: .93rem;
    font-weight: 900;
    color: #203958;
    overflow-wrap: anywhere;
}

.attack-meta {
    color: #647b96;
    font-size: .75rem;
    line-height: 1.9;
    margin-top: 8px;
    overflow-wrap: anywhere;
}

.attack-ip {
    color:#167da5;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-weight:800;
}

/* SMALL GLASS CARDS */

.mini-card {
    padding: 14px 15px;
    border-radius: 17px;
    margin-bottom: 10px;
    min-height: 88px;
}

.mini-label {
    color: #71849d;
    text-transform: uppercase;
    font-size: .62rem;
    font-weight: 850;
    letter-spacing: .06em;
}

.mini-value {
    color: #203958;
    font-size: 1.28rem;
    font-weight: 900;
    letter-spacing: -.03em;
    margin-top: 7px;
    overflow-wrap: anywhere;
}

.mini-note {
    color:#7a8da5;
    font-size:.67rem;
    margin-top:4px;
    overflow-wrap:anywhere;
}

/* EMPTY STATE AND FOOTER */

.empty-state {
    padding: 25px;
    border-radius: 22px;
    text-align: center;
    background: rgba(255,255,255,.62);
    border: 1px dashed rgba(131,163,205,.47);
    box-shadow: inset 0 1px 0 rgba(255,255,255,.9);
}

.empty-icon {font-size:1.8rem;}
.empty-title {color:#29415e;font-size:.96rem;font-weight:850;margin-top:8px;}
.empty-text {color:#788ca4;font-size:.77rem;margin-top:5px;}
.footer-note {
    color:#8496ac;
    text-align:center;
    font-size:.67rem;
    padding:27px 0 4px;
    letter-spacing:.06em;
}

/* STREAMLIT CONTROLS */

div.stButton>button, div.stDownloadButton>button {
    border-radius: 14px;
    border: 1px solid rgba(255,255,255,.95);
    background: linear-gradient(135deg,
        rgba(255,255,255,.92),
        rgba(221,236,255,.76));
    color: #25466c;
    font-weight: 800;
    min-height: 42px;
    box-shadow:
        0 6px 17px rgba(68,105,159,.10),
        inset 0 1px 0 white;
    transition: all .18s ease;
}

div.stButton>button:hover, div.stDownloadButton>button:hover {
    background: linear-gradient(135deg,#e4f1ff,#eae5ff);
    border-color: #9bc4ff;
    color: #174b8b;
    transform: translateY(-1px);
}

div.stButton>button[kind="primary"] {
    background: linear-gradient(135deg,#347cf6,#6e8df5);
    border-color: rgba(255,255,255,.72);
    color: white;
}

[data-testid="stExpander"] {
    border: 1px solid rgba(255,255,255,.92);
    border-radius: 17px;
    background: rgba(255,255,255,.58);
    box-shadow: 0 7px 20px rgba(68,105,159,.07);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    margin-bottom: 9px;
}

[data-testid="stExpander"] summary {
    padding: 12px 14px;
    color: #29415e;
}

[data-testid="stMetric"] {
    background: rgba(255,255,255,.68);
    border: 1px solid rgba(255,255,255,.95);
    border-radius: 17px;
    box-shadow: 0 8px 20px rgba(68,105,159,.07);
    padding: 12px;
}

[data-testid="stMetricLabel"] {color:#71849d!important;}
[data-testid="stMetricValue"] {color:#203958!important;}

.stProgress>div>div>div {
    background: linear-gradient(90deg,#5a8cf6,#53d1dc);
}

[data-baseweb="select"]>div {
    background: rgba(255,255,255,.8)!important;
    border-color: rgba(139,169,209,.55)!important;
    border-radius: 12px!important;
    color: #29415e!important;
}

[data-baseweb="select"] * {color:#29415e!important;}

[data-baseweb="popover"],[data-baseweb="menu"],[role="listbox"] {
    background: #f5f8ff!important;
    color: #29415e!important;
    border: 1px solid #d8e5f7!important;
}

[role="option"] {
    background: #f5f8ff!important;
    color: #29415e!important;
}

[role="option"]:hover {background:#e4eeff!important;}

[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea {
    background: rgba(255,255,255,.82)!important;
    border: 1px solid rgba(139,169,209,.55)!important;
    border-radius: 12px!important;
    color: #203958!important;
}

[data-testid="stTextInput"] input::placeholder {
    color:#8a9bb1!important;
    opacity:1;
}

[data-testid="stCaptionContainer"] {
    color: #788ca4;
}

[data-testid="stAlert"] {
    border-radius: 15px;
}

hr {
    border-color: rgba(132,163,204,.24);
}

@media(max-width:768px) {
    .block-container {
        padding-left:.7rem;
        padding-right:.7rem;
    }
    .hero {
        min-height:auto;
        padding:21px;
    }
    .metric-card {padding:15px;}
    .bar-row {
        grid-template-columns:minmax(75px,1fr) minmax(55px,1.5fr) 30px;
        gap:6px;
    }
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# UI HELPERS
# ============================================================

def metric_card(label, value, caption, accent="#3478f6"):
    st.markdown(
        f'<div class="metric-card" style="--accent:{escape(str(accent))}">'
        f'<div class="metric-label">{escape(str(label))}</div>'
        f'<div class="metric-value">{escape(str(value))}</div>'
        f'<div class="metric-caption">{escape(str(caption))}</div></div>',
        unsafe_allow_html=True,
    )


def mini_card(label, value, note="", accent="#45b8d8"):
    st.markdown(
        f'<div class="mini-card" style="border-top:2px solid {escape(str(accent))}">'
        f'<div class="mini-label">{escape(str(label))}</div>'
        f'<div class="mini-value">{escape(str(value))}</div>'
        f'<div class="mini-note">{escape(str(note))}</div></div>',
        unsafe_allow_html=True,
    )


def module_card(icon, title, description, status="ACTIVE"):
    st.markdown(
        f'<div class="module-card"><span class="module-icon">{escape(str(icon))}</span>'
        f'<span class="pill">{escape(str(status))}</span>'
        f'<div class="module-title">{escape(str(title))}</div>'
        f'<div class="module-description">{escape(str(description))}</div></div>',
        unsafe_allow_html=True,
    )


def section_header(icon, title, description):
    st.markdown(
        f'<div class="section-header"><div class="section-icon">{escape(str(icon))}</div>'
        f'<div><div class="section-title">{escape(str(title))}</div>'
        f'<div class="section-description">{escape(str(description))}</div></div></div>',
        unsafe_allow_html=True,
    )


def severity_badge(severity):
    severity = safe_value(severity, "MEDIUM").upper()
    css = (
        "red" if severity in ("CRITICAL", "HIGH")
        else "amber" if severity == "MEDIUM"
        else "green"
    )
    return f'<span class="severity {css}">{escape(severity)}</span>'


def empty_state(title, description, icon="📭"):
    st.markdown(
        f'<div class="empty-state"><div class="empty-icon">{escape(str(icon))}</div>'
        f'<div class="empty-title">{escape(str(title))}</div>'
        f'<div class="empty-text">{escape(str(description))}</div></div>',
        unsafe_allow_html=True,
    )


def render_bar_panel(title, subtitle, counts, max_items=8):
    st.markdown(
        f'<div class="panel"><div class="panel-title">{escape(str(title))}</div>'
        f'<div class="panel-subtitle">{escape(str(subtitle))}</div>',
        unsafe_allow_html=True,
    )

    if not counts:
        st.markdown(
            '<div class="panel-subtitle">No matching recorded data yet.</div></div>',
            unsafe_allow_html=True,
        )
        return

    items = (
        counts.most_common(max_items)
        if isinstance(counts, Counter)
        else list(counts.items())[:max_items]
    )

    maximum = max((value for _, value in items), default=1) or 1

    for label, value in items:
        width = max(4, int(value / maximum * 100))
        st.markdown(
            f'<div class="bar-row"><div class="bar-label">{escape(str(label))}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width}%"></div></div>'
            f'<div class="bar-count">{escape(str(value))}</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)


def render_event_table(events, limit=25):
    if not events:
        empty_state(
            "No matching records",
            "There are no events matching the current selection.",
        )
        return

    widths = [1.7, 1, 1.8, .8, .7, 1]
    labels = ["Timestamp", "Source IP", "Attack / Event", "Severity", "Method", "Action"]
    header = st.columns(widths)

    for column, label in zip(header, labels):
        column.markdown(
            f'<div class="table-head">{escape(label)}</div>',
            unsafe_allow_html=True,
        )

    for event in events[:limit]:
        cols = st.columns(widths)

        for column, value in zip(
            cols[:3],
            [event["timestamp"], event["source_ip"], event["attack_name"]],
        ):
            css = (
                "table-cell ip"
                if value == event["source_ip"]
                else "table-cell"
            )
            column.markdown(
                f'<div class="{css}">{escape(str(value))}</div>',
                unsafe_allow_html=True,
            )

        cols[3].markdown(
            severity_badge(event["severity"]),
            unsafe_allow_html=True,
        )
        cols[4].markdown(
            f'<div class="table-cell">{escape(event["method"])}</div>',
            unsafe_allow_html=True,
        )
        cols[5].markdown(
            f'<div class="table-cell">{escape(event["action"])}</div>',
            unsafe_allow_html=True,
        )


def marker_for(event):
    if event["severity"] in ("CRITICAL", "HIGH"):
        return "🔴"
    if event["severity"] == "MEDIUM":
        return "🟠"
    return "🟢"


def render_attack_card(event, unread=False):
    severity = event["severity"]
    accent = (
        "#e94b65" if severity in ("CRITICAL", "HIGH")
        else "#d99a28" if severity == "MEDIUM"
        else "#28a879"
    )

    new_tag = (
        '<span class="pill" style="color:#bd3c50;border-color:rgba(223,68,91,.3)">NEW ALERT</span>'
        if unread else ""
    )

    st.markdown(
        f'<div class="attack-card" style="--attack-accent:{accent}">{new_tag}'
        f'<div class="attack-name">{marker_for(event)} {escape(event["attack_name"])}</div>'
        f'<div class="attack-meta"><b>Source IP:</b> '
        f'<span class="attack-ip">{escape(event["source_ip"])}</span><br>'
        f'<b>Severity:</b> {escape(severity)}<br>'
        f'<b>Timestamp:</b> {escape(event["timestamp"])}<br>'
        f'<b>Request:</b> {escape(event["method"])} {escape(event["path"])}<br>'
        f'<b>Action:</b> {escape(event["action"])}</div></div>',
        unsafe_allow_html=True,
    )


def compact_attack_row(event, index):
    
    label = (
        f'{marker_for(event)} {event["attack_name"]} | '
        f'{event["source_ip"]} | {event["timestamp"]}'
    )

    with st.expander(label, expanded=False):
        render_attack_card(
            event,
            unread=event["id"] not in st.session_state.read_alerts,
        )

        if event["categories"]:
            st.write(
                "**Signature categories:**",
                ", ".join(map(str, event["categories"])),
            )

        cols = st.columns(3)
        cols[0].markdown(f'**Method**  \n`{event["method"]}`')
        cols[1].markdown(f'**Path**  \n`{event["path"]}`')
        cols[2].markdown(f'**Action**  \n`{event["action"]}`')

        with st.expander("View original log fields"):
            st.json(event["details"])


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

pages = [
    "Overview",
    "HTTP Request Inspection",
    "Attack Signature Identification",
    "Behavior Monitoring & Rate Limiting",
    "Log Analysis",
    "Dashboard Interpretation",
    "🔔 Attack Alerts",
]

with st.sidebar:
    st.markdown("## 🛡️ SentinelShield")
    st.caption("ADVANCED INTRUSION DETECTION")
    st.markdown("---")

    page = st.radio(
        "SECURITY CONSOLE",
        pages,
        index=0,
        key="main_navigation",
    )

    st.markdown("---")
    st.markdown("### System Status")
    st.markdown("🟢 **Dashboard:** Online")
    st.markdown(
        "🟢 **Security Log:** Available"
        if LOG_FILE
        else "🟡 **Security Log:** Not found"
    )
    st.markdown(f"📜 **Events loaded:** {len(EVENTS)}")
    st.markdown(f"🚨 **Attack events:** {len(ATTACK_EVENTS)}")
    st.markdown("---")

    if st.button("↻ Refresh Dashboard", use_container_width=True):
        st.rerun()


# ============================================================
# HEADER AND ALERT BELL
# ============================================================

if st.session_state.pop("open_alert_center", False):
    page = "🔔 Attack Alerts"

left, right = st.columns([7.2, 1], gap="small")

with left:
    st.markdown(
        '<div class="hero"><div class="hero-kicker">SECURITY OPERATIONS CENTER / SOC</div>'
        '<div class="hero-title">SentinelShield</div>'
        '<div class="hero-subtitle">Advanced Intrusion Detection &amp; Web Protection System</div>'
        '<div class="hero-status">● MONITORING CONSOLE READY</div></div>',
        unsafe_allow_html=True,
    )
    
with right:
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    unread_count = len(UNREAD_ALERTS)

    # Small floating notification popup
    with st.popover(
        f"🔔 {unread_count}" if unread_count else "🔔 Alerts",
        use_container_width=True,
    ):
        st.markdown("### 🔔 Security Notifications")
        st.caption(f"{unread_count} unread alert(s)")

        if UNREAD_ALERTS:
            for event in UNREAD_ALERTS[:5]:
                severity = event["severity"]

                st.markdown(
                    f"**{marker_for(event)} {event['attack_name']}**"
                )
                st.caption(
                    f"Severity: {severity}  ·  "
                    f"IP: {event['source_ip']}"
                )
                st.caption(
                    f"{event['method']} {event['path']}"
                )
                st.caption(event["timestamp"])
                st.divider()
        else:
            st.success("No unread security alerts.")

        if st.button(
            "Open Alert Center →",
            key="open_alert_center_button",
            use_container_width=True,
        ):
            st.session_state.show_alert_panel = False
            st.session_state.open_alert_center = True
            st.rerun()



# ============================================================
# PAGE 1 - OVERVIEW
# ============================================================

if page == "Overview":
    section_header(
        "🛰️",
        "Security Overview",
        "A clean snapshot of recorded security activity.",
    )

    attack_ips = {
        e["source_ip"] for e in ATTACK_EVENTS
        if e["source_ip"] not in ("Unknown", "—")
    }

    high_risk = sum(
        e["severity"] in ("HIGH", "CRITICAL")
        for e in ATTACK_EVENTS
    )

    cols = st.columns(4)
    cards = [
        ("Security Events", f"{len(EVENTS):,}", "Parsed log records", "#39b8d5"),
        ("Attack Indicators", f"{len(ATTACK_EVENTS):,}", "Attack-related records", "#e85d75"),
        ("High / Critical", f"{high_risk:,}", "High-severity attack records", "#d99a28"),
        ("Source IPs", f"{len(attack_ips):,}", "Distinct attack-source IPs", "#8871f8"),
    ]

    for col, item in zip(cols, cards):
        with col:
            metric_card(*item)

    st.markdown("### 🧩 Security Modules")

    c1, c2 = st.columns(2)

    with c1:
        module_card(
            "🌐",
            "HTTP Request Inspection",
            "Inspect HTTP methods, request paths, source IPs and recorded outcomes.",
        )
        module_card(
            "📈",
            "Behavior Monitoring & Rate Limiting",
            "Review request volume, source activity, blocked actions and rate-limit events.",
        )
        module_card(
            "🧭",
            "Dashboard Interpretation",
            "Compare severity, attack categories and protective actions.",
        )

    with c2:
        module_card(
            "📜",
            "Log Analysis",
            "Search event records with readable filters and inspect original log fields.",
        )
        module_card(
            "🧬",
            "Attack Signature Identification",
            "Review recorded SQL injection, XSS, path traversal and command injection signatures.",
        )

    st.markdown("### 🚨 Recent Attack Activity")
    st.caption("Select an alert row to open its full event details.")

    if ATTACK_EVENTS:
        for idx, event in enumerate(ATTACK_EVENTS[:8]):
            compact_attack_row(event, idx)
    else:
        empty_state(
            "No attack indicators found",
            "No attack-related records were found in the current security log.",
        )

    if not LOG_FILE:
        st.warning(
            "security_events.jsonl was not found. Check the project's Log Analysis folder."
        )


# ============================================================
# PAGE 2 - HTTP REQUEST INSPECTION
# ============================================================

elif page == "HTTP Request Inspection":
    section_header(
        "🌐",
        "HTTP Request Inspection",
        "Filter recorded requests by method and search event details.",
    )

    methods = sorted({
        e["method"] for e in EVENTS
        if e["method"] not in ("—", "Unknown")
    })

    paths = {
        e["path"] for e in EVENTS
        if e["path"] != "—"
    }

    cols = st.columns(3)

    with cols[0]:
        metric_card("Logged Requests", len(EVENTS), "Available event records")

    with cols[1]:
        metric_card(
            "HTTP Methods",
            len(methods),
            "Distinct observed methods",
            "#8871f8",
        )

    with cols[2]:
        metric_card(
            "Request Paths",
            len(paths),
            "Distinct paths in logs",
            "#28a879",
        )

    st.markdown("### Request Records")

    filter_col, search_col = st.columns([1, 2])

    with filter_col:
        method_filter = st.selectbox(
            "HTTP Method",
            ["All"] + methods,
            index=0,
            key="http_method_filter",
        )

    with search_col:
        request_query = st.text_input(
            "Search requests",
            placeholder="Search IP, path, attack, action…",
            key="http_request_search",
        )

    filtered = EVENTS

    if method_filter != "All":
        filtered = [
            e for e in filtered
            if e["method"] == method_filter
        ]

    if request_query.strip():
        term = request_query.strip().lower()

        filtered = [
            e for e in filtered
            if term in " ".join([
                e["source_ip"],
                e["path"],
                e["method"],
                e["attack_name"],
                e["severity"],
                e["action"],
                e["timestamp"],
            ]).lower()
        ]

    st.caption(f"Showing {len(filtered)} matching record(s).")
    render_event_table(filtered, limit=100)


# ============================================================
# PAGE 3 - ATTACK SIGNATURE IDENTIFICATION
# ============================================================

elif page == "Attack Signature Identification":
    section_header(
        "🧬",
        "Attack Signature Identification",
        "Frequency and classification of signatures recorded by the security logger.",
    )

    signature_counts = Counter()

    for event in ATTACK_EVENTS:
        labels = event["categories"] or [event["attack_name"]]

        for label in labels:
            signature_counts[
                str(label).replace("_", " ").upper()
            ] += 1

    cols = st.columns(3)

    with cols[0]:
        metric_card(
            "Attack Events",
            len(ATTACK_EVENTS),
            "Attack-related records",
            "#e85d75",
        )

    with cols[1]:
        metric_card(
            "Signature Types",
            len(signature_counts),
            "Distinct signature labels",
            "#8871f8",
        )

    with cols[2]:
        metric_card(
            "High / Critical",
            sum(
                e["severity"] in ("HIGH", "CRITICAL")
                for e in ATTACK_EVENTS
            ),
            "Priority review events",
            "#d99a28",
        )

    left, right = st.columns([1.25, 1], gap="medium")

    with left:
        render_bar_panel(
            "Signature Frequency",
            "Most frequent attack labels, displayed in a compact glass panel.",
            signature_counts,
            max_items=8,
        )

    with right:
        top_signature = (
            signature_counts.most_common(1)[0]
            if signature_counts
            else ("No data", 0)
        )

        st.markdown(
            '<div class="panel"><div class="panel-title">Signature Overview</div>'
            '<div class="panel-subtitle">Summary of signatures in the current log.</div>',
            unsafe_allow_html=True,
        )

        mini_card(
            "Most Frequent Signature",
            top_signature[0],
            f"{top_signature[1]} recorded event(s)",
            "#e85d75",
        )

        mini_card(
            "Signature Categories",
            len(signature_counts),
            "Unique normalized labels",
            "#8871f8",
        )

        mini_card(
            "Attack Events",
            len(ATTACK_EVENTS),
            "Total attack-related records",
            "#39b8d5",
        )

        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("### Recorded Attack Details")
    render_event_table(ATTACK_EVENTS, limit=100)


# ============================================================
# PAGE 4 - BEHAVIOR MONITORING & RATE LIMITING
# ============================================================

elif page == "Behavior Monitoring & Rate Limiting":
    section_header(
        "📈",
        "Behavior Monitoring & Rate Limiting",
        "Source-IP behavior, event volume and recorded protection outcomes.",
    )

    blocked_count = sum("BLOCK" in e["action"] for e in EVENTS)

    allowed_count = sum(
        any(word in e["action"] for word in ("ALLOW", "PASS", "NORMAL"))
        for e in EVENTS
    )

    suspicious_count = sum(
        e["severity"] in ("HIGH", "CRITICAL") or is_attack(e)
        for e in EVENTS
    )

    top_ip, top_ip_count = (
        IP_COUNTS.most_common(1)[0]
        if IP_COUNTS
        else ("No data", 0)
    )

    cols = st.columns(4)

    with cols[0]:
        metric_card(
            "Requests / Events",
            len(EVENTS),
            "Total parsed log records",
            "#39b8d5",
        )

    with cols[1]:
        metric_card(
            "Blocked Actions",
            blocked_count,
            "Actions explicitly marked blocked",
            "#e85d75",
        )

    with cols[2]:
        metric_card(
            "Rate-Limit Events",
            len(RATE_LIMIT_EVENTS),
            "Explicit rate-limit records",
            "#d99a28",
        )

    with cols[3]:
        metric_card(
            "Suspicious Indicators",
            suspicious_count,
            "Attack-related or high-risk records",
            "#8871f8",
        )

    st.markdown("### 🧠 Behavior Summary")

    summary_cols = st.columns(4)

    with summary_cols[0]:
        mini_card(
            "Unique Source IPs",
            len(IP_COUNTS),
            "Observed in event records",
            "#39b8d5",
        )

    with summary_cols[1]:
        mini_card(
            "Attack Records",
            len(ATTACK_EVENTS),
            "Attack-related entries",
            "#e85d75",
        )

    with summary_cols[2]:
        mini_card(
            "Allowed / Normal",
            allowed_count,
            "Explicit allow/pass/normal actions",
            "#28a879",
        )

    with summary_cols[3]:
        mini_card(
            "Top IP Event Count",
            top_ip_count,
            top_ip,
            "#d99a28",
        )

    left, right = st.columns([1.15, 1], gap="medium")

    with left:
        render_bar_panel(
            "Most Active Source IPs",
            "Top sources by total recorded events. Counts alone do not prove malicious activity.",
            IP_COUNTS,
            max_items=7,
        )

    with right:
        render_bar_panel(
            "Recorded Action Breakdown",
            "Distribution of action labels found in the log.",
            ACTION_COUNTS,
            max_items=6,
        )

    st.markdown("### Rate-Limit Records")

    if RATE_LIMIT_EVENTS:
        render_event_table(RATE_LIMIT_EVENTS, limit=100)


# ============================================================
# PAGE 5 - LOG ANALYSIS
# ============================================================

elif page == "Log Analysis":
    section_header(
        "📜",
        "Log Analysis",
        "Search and filter security records using readable dropdowns.",
    )

    cols = st.columns(3)

    with cols[0]:
        metric_card(
            "Log Status",
            "Available" if LOG_FILE else "Not Found",
            "security_events.jsonl",
        )

    with cols[1]:
        metric_card(
            "Parsed Records",
            len(EVENTS),
            "Valid JSON records",
            "#8871f8",
        )

    with cols[2]:
        metric_card(
            "Unread Alerts",
            len(UNREAD_ALERTS),
            "Attack alerts not marked read",
            "#e85d75",
        )

    if LOG_FILE:
        st.caption(f"Log source: {LOG_FILE}")

    st.markdown("### Search Event Records")

    search_col, severity_col, action_col = st.columns([2, 1, 1])

    with search_col:
        query = st.text_input(
            "Search logs",
            placeholder="Type IP, path, method, signature, severity…",
            key="log_search",
        )

    severity_values = sorted({
        e["severity"] for e in EVENTS
        if e["severity"] != "Unknown"
    })

    action_values = sorted({
        e["action"] for e in EVENTS
        if e["action"] != "Unknown"
    })

    with severity_col:
        selected_severity = st.selectbox(
            "Severity",
            ["All"] + severity_values,
            index=0,
            key="log_severity_filter",
        )

    with action_col:
        selected_action = st.selectbox(
            "Action",
            ["All"] + action_values,
            index=0,
            key="log_action_filter",
        )

    filtered = EVENTS

    if query.strip():
        term = query.strip().lower()

        filtered = [
            e for e in filtered
            if (
                term in json.dumps(
                    e["details"],
                    ensure_ascii=False,
                    default=str,
                ).lower()
                or term in " ".join([
                    e["source_ip"],
                    e["path"],
                    e["method"],
                    e["attack_name"],
                    e["severity"],
                    e["action"],
                    e["timestamp"],
                ]).lower()
            )
        ]

    if selected_severity != "All":
        filtered = [
            e for e in filtered
            if e["severity"] == selected_severity
        ]

    if selected_action != "All":
        filtered = [
            e for e in filtered
            if e["action"] == selected_action
        ]

    st.caption(
        f"{len(filtered)} matching record(s) out of {len(EVENTS)}."
    )

    render_event_table(filtered, limit=100)

    if LOG_FILE:
        try:
            st.download_button(
                "⬇️ Download Security Event Log",
                data=LOG_FILE.read_bytes(),
                file_name="security_events.jsonl",
                mime="application/x-ndjson",
                use_container_width=True,
            )
        except OSError:
            st.warning("The log file could not be read for download.")


# ============================================================
# PAGE 6 - DASHBOARD INTERPRETATION
# ============================================================

elif page == "Dashboard Interpretation":
    section_header(
        "🧭",
        "Dashboard Interpretation",
        "Visual summaries for severity, attack families and recorded protection actions.",
    )

    high = sum(
        e["severity"] in ("HIGH", "CRITICAL")
        for e in EVENTS
    )

    medium = sum(e["severity"] == "MEDIUM" for e in EVENTS)

    low_info = sum(
        e["severity"] in ("LOW", "INFO")
        for e in EVENTS
    )

    blocked = sum("BLOCK" in e["action"] for e in EVENTS)

    detected = sum("DETECT" in e["action"] for e in EVENTS)

    cols = st.columns(4)

    with cols[0]:
        metric_card(
            "High / Critical",
            high,
            "Recorded high-priority events",
            "#e85d75",
        )

    with cols[1]:
        metric_card(
            "Medium Severity",
            medium,
            "Recorded medium-priority events",
            "#d99a28",
        )

    with cols[2]:
        metric_card(
            "Low / Info",
            low_info,
            "Recorded lower-severity events",
            "#28a879",
        )

    with cols[3]:
        metric_card(
            "Blocked Actions",
            blocked,
            "Actions explicitly marked blocked",
            "#8871f8",
        )

    category_counts = Counter(
        str(category).replace("_", " ").upper()
        for event in ATTACK_EVENTS
        for category in (
            event["categories"] or [event["attack_name"]]
        )
    )

    left, right = st.columns(2, gap="medium")

    with left:
        render_bar_panel(
            "Severity Distribution",
            "Count of event records by severity.",
            SEVERITY_COUNTS,
            max_items=6,
        )

        render_bar_panel(
            "Attack Category Breakdown",
            "Most common labels in attack-related records.",
            category_counts,
            max_items=7,
        )

    with right:
        render_bar_panel(
            "Protection Action Breakdown",
            "Action labels as written in the log.",
            ACTION_COUNTS,
            max_items=7,
        )

    st.markdown("### 🧭 Interpretation Guide")

    guide_cols = st.columns(2, gap="medium")

    with guide_cols[0]:
        module_card(
            "🟢",
            "LOW / INFO",
            "Lower recorded severity. Review surrounding requests if activity is unusual.",
            "GUIDE",
        )

        module_card(
            "🟠",
            "MEDIUM",
            "Review the signature, source IP and endpoint for context.",
            "GUIDE",
        )

    with guide_cols[1]:
        module_card(
            "🔴",
            "HIGH / CRITICAL",
            "Prioritize request details and the recorded protective action.",
            "GUIDE",
        )

        module_card(
            "🛡️",
            "BLOCKED / RATE LIMITED",
            f"{blocked} blocked action(s) and {len(RATE_LIMIT_EVENTS)} explicit rate-limit event(s) are present in this log.",
            "LOG DATA",
        )

    st.markdown("### Latest High-Priority Events")

    priority_events = [
        e for e in EVENTS
        if e["severity"] in ("HIGH", "CRITICAL")
    ]

    if priority_events:
        for idx, event in enumerate(priority_events[:5]):
            compact_attack_row(event, idx)
    else:
        empty_state(
            "No high-priority severity records",
            "No HIGH or CRITICAL severity labels were found in the current log.",
        )


# ============================================================
# PAGE 7 - ATTACK ALERT CENTER
# ============================================================

elif page == "🔔 Attack Alerts":
    section_header(
        "🔔",
        "Attack Alert Center",
        "Open an alert row to inspect the full IP, signature and request details.",
    )

    high_alerts = sum(
        e["severity"] in ("HIGH", "CRITICAL")
        for e in ATTACK_EVENTS
    )

    cols = st.columns(3)

    with cols[0]:
        metric_card(
            "Unread Alerts",
            len(UNREAD_ALERTS),
            "Not marked as read",
            "#e85d75",
        )

    with cols[1]:
        metric_card(
            "Attack Events",
            len(ATTACK_EVENTS),
            "Attack-related log records",
            "#d99a28",
        )

    with cols[2]:
        metric_card(
            "High / Critical",
            high_alerts,
            "Priority review",
            "#8871f8",
        )

    b1, b2 = st.columns(2)

    with b1:
        if st.button(
            "✓ Mark All Alerts as Read",
            disabled=not UNREAD_ALERTS,
            use_container_width=True,
        ):
            st.session_state.read_alerts.update(
                e["id"] for e in UNREAD_ALERTS
            )
            st.rerun()

    with b2:
        if st.button("↻ Refresh Alerts", use_container_width=True):
            st.rerun()

    if not ATTACK_EVENTS:
        empty_state(
            "No attack-related events found",
            "Alerts appear when attack-related records are written to the security log.",
            "🛡️",
        )

        if not LOG_FILE:
            st.info(
                "Check that security_events.jsonl exists in the Log Analysis folder."
            )

    else:
        for index, event in enumerate(ATTACK_EVENTS[:100]):
            unread = event["id"] not in st.session_state.read_alerts
            prefix = "🆕 " if unread else ""

            label = (
                f'{prefix}{marker_for(event)} {event["attack_name"]} | '
                f'{event["source_ip"]} | {event["timestamp"]}'
            )

            with st.expander(
                label,
                expanded=(index == 0 and unread),
            ):
                render_attack_card(event, unread=unread)

                details_cols = st.columns(3)

                with details_cols[0]:
                    mini_card(
                        "Attack Name",
                        event["attack_name"],
                        "Recorded signature",
                        "#e85d75",
                    )

                with details_cols[1]:
                    mini_card(
                        "Source IP",
                        event["source_ip"],
                        "From event log",
                        "#39b8d5",
                    )

                with details_cols[2]:
                    mini_card(
                        "Severity / Action",
                        f'{event["severity"]} / {event["action"]}',
                        event["timestamp"],
                        "#d99a28",
                    )

                if event["categories"]:
                    st.write(
                        "**Signature categories:**",
                        ", ".join(map(str, event["categories"])),
                    )

                st.markdown("### Request Details")

                req_cols = st.columns(3)
                req_cols[0].markdown(
                    f'**Method**  \n`{event["method"]}`'
                )
                req_cols[1].markdown(
                    f'**Path**  \n`{event["path"]}`'
                )
                req_cols[2].markdown(
                    f'**Action**  \n`{event["action"]}`'
                )

                with st.expander("View original log fields"):
                    st.json(event["details"])

                if unread and st.button(
                    "Mark This Alert as Read",
                    key=f"mark_read_{index}",
                ):
                    st.session_state.read_alerts.add(event["id"])
                    st.rerun()


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    '<div class="footer-note">'
    'SENTINELSHIELD • SECURITY EVENT MONITORING • AUTHORIZED SECURITY TESTING ONLY'
    '</div>',
    unsafe_allow_html=True,
)
