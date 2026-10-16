
import json
import os
import shutil
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "security_events.jsonl")

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
WHITE = "\033[97m"


def terminal_width():
    return max(110, min(shutil.get_terminal_size((140, 35)).columns, 180))


def read_events():
    events = []
    invalid_lines = 0

    if not os.path.isfile(LOG_FILE):
        return events, invalid_lines, False

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
                else:
                    invalid_lines += 1
            except json.JSONDecodeError:
                invalid_lines += 1

    return events, invalid_lines, True


def action_of(event):
    return str(event.get("action", "UNKNOWN")).upper()


def severity_of(event):
    return str(event.get("severity", "UNKNOWN")).upper()


def is_allowed(event):
    return action_of(event) in ("ALLOWED", "ALLOW")


def is_blocked(event):
    action = action_of(event)
    return any(word in action for word in ("BLOCK", "DENY", "RATE_LIMIT"))


def is_suspicious(event):
    return "SUSPICIOUS" in action_of(event)


def categories_of(event):
    categories = event.get("categories", [])
    if isinstance(categories, list):
        return [str(item) for item in categories if item]
    if categories:
        return [str(categories)]
    return []


def border(width, color=CYAN):
    print(color + "+" + "-" * (width - 2) + "+" + RESET)


def heading(text, width):
    print(CYAN + "+" + "-" * (width - 2) + "+" + RESET)
    print(CYAN + "|" + RESET + BOLD + text.center(width - 2) + RESET
          + CYAN + "|" + RESET)
    border(width)


def print_summary(events, invalid_lines, width):
    allowed = sum(is_allowed(event) for event in events)
    blocked = sum(is_blocked(event) for event in events)
    suspicious = sum(is_suspicious(event) for event in events)
    high = sum(severity_of(event) == "HIGH" for event in events)
    critical = sum(severity_of(event) == "CRITICAL" for event in events)

    metrics = [
        ("TOTAL EVENTS", len(events), CYAN),
        ("ALLOWED", allowed, GREEN),
        ("BLOCKED / DENIED", blocked, RED),
        ("SUSPICIOUS", suspicious, YELLOW),
        ("HIGH / CRITICAL", high + critical, RED),
        ("INVALID LINES", invalid_lines, YELLOW if invalid_lines else GREEN),
    ]

    columns = 3
    gap = 2
    card_width = (width - gap * (columns - 1)) // columns

    print()
    heading("SECURITY EVENT SUMMARY", width)

    for start in range(0, len(metrics), columns):
        row = metrics[start:start + columns]
        parts = []
        for label, value, color in row:
            text = f"{label}: {value}"
            text = text[:card_width - 4].ljust(card_width - 4)
            parts.append("| " + color + BOLD + text + RESET + " |")
        print((" " * gap).join(parts))

    print()


def print_breakdowns(events, width):
    severities = Counter(severity_of(event) for event in events)
    categories = Counter()

    for event in events:
        categories.update(categories_of(event))

    gap = 4
    panel_width = (width - gap) // 2

    heading("SEVERITY & ATTACK CATEGORY ANALYSIS", width)

    left_lines = ["SEVERITY BREAKDOWN"]
    right_lines = ["ATTACK CATEGORY BREAKDOWN"]

    if severities:
        left_lines.extend(
            f"{key}: {value}" for key, value in severities.most_common()
        )
    else:
        left_lines.append("No severity data recorded.")

    if categories:
        right_lines.extend(
            f"{key}: {value}" for key, value in categories.most_common()
        )
    else:
        right_lines.append("No attack categories recorded.")

    row_count = max(len(left_lines), len(right_lines))

    for index in range(row_count):
        left = left_lines[index] if index < len(left_lines) else ""
        right = right_lines[index] if index < len(right_lines) else ""

        left = left[:panel_width - 4].ljust(panel_width - 4)
        right = right[:panel_width - 4].ljust(panel_width - 4)

        print(
            BLUE + "| " + RESET + BOLD + left + RESET + " |"
            + " " * gap
            + BLUE + "| " + RESET + BOLD + right + RESET + " |"
        )

    print()


def event_card(event, number, card_width):
    timestamp = str(event.get("timestamp", "N/A"))
    ip = str(event.get("source_ip", "N/A"))
    method = str(event.get("method", "N/A"))
    path = str(event.get("path", "N/A"))
    severity = severity_of(event)
    action = action_of(event)
    category = ", ".join(categories_of(event)) or "NONE"

    if is_allowed(event):
        action_color = GREEN
    elif is_blocked(event) or is_suspicious(event):
        action_color = RED
    else:
        action_color = YELLOW

    severity_color = (
        RED if severity in ("HIGH", "CRITICAL")
        else YELLOW if severity == "MEDIUM"
        else WHITE
    )

    fields = [
        (f"LOG {number}", BOLD + CYAN),
        (f"Time: {timestamp}", WHITE),
        (f"IP: {ip}", WHITE),
        (f"Request: {method} {path}", WHITE),
        (f"Category: {category}", YELLOW if category != "NONE" else WHITE),
        (f"Severity: {severity}", severity_color),
        (f"Action: {action}", action_color),
    ]

    content_width = card_width - 4
    lines = []

    for text, color in fields:
        text = text[:content_width].ljust(content_width)
        lines.append("| " + color + text + RESET + " |")

    return lines


def print_latest_events(events, width):
    heading("LATEST 10 SECURITY EVENTS", width)

    if not events:
        print(YELLOW + "No events found in the log file." + RESET)
        return

    recent = list(reversed(events[-10:]))

    columns = 3
    gap = 2
    card_width = (width - gap * (columns - 1)) // columns

    cards = [
        event_card(event, index, card_width)
        for index, event in enumerate(recent, start=1)
    ]

    blank_card = ["| " + " " * (card_width - 4) + " |"] * 7

    while len(cards) % columns:
        cards.append(blank_card)

    top = "+" + "-" * (card_width - 2) + "+"
    print(CYAN + top * columns + RESET)

    for start in range(0, len(cards), columns):
        row = cards[start:start + columns]
        row_height = max(len(card) for card in row)

        for line_index in range(row_height):
            parts = []
            for card in row:
                line = (
                    card[line_index]
                    if line_index < len(card)
                    else "| " + " " * (card_width - 4) + " |"
                )
                parts.append(line)

            print((" " * gap).join(parts))

        print(CYAN + top * columns + RESET)


def main():
    width = terminal_width()
    events, invalid_lines, file_found = read_events()

    print()
    heading("SENTINELSHIELD | SECURITY EVENT LOG REPORT", width)
    print(f"Log source: {LOG_FILE}")

    if not file_found:
        print(RED + "ERROR: Security event log file was not found." + RESET)
        return

    print_summary(events, invalid_lines, width)
    print_breakdowns(events, width)
    print_latest_events(events, width)

    print()
    print(CYAN + "=" * width + RESET)
    print(BOLD + GREEN + "SECURITY EVENT LOG ANALYSIS COMPLETE".center(width) + RESET)
    print(CYAN + "=" * width + RESET)


if __name__ == "__main__":
    main()
