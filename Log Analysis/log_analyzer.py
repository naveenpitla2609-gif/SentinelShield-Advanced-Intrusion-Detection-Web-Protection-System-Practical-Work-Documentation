
import json
import os
import shutil
from collections import Counter

LOG_FILE = os.path.join("logs", "security_events.jsonl")

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
WHITE = "\033[97m"


def read_logs():
    events = []
    invalid_lines = 0

    if not os.path.exists(LOG_FILE):
        print(f"\nERROR: Log file not found: {LOG_FILE}")
        return events, invalid_lines

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
                else:
                    invalid_lines += 1
            except json.JSONDecodeError:
                invalid_lines += 1

    return events, invalid_lines


def action_of(event):
    return str(event.get("action", "UNKNOWN")).upper().strip()


def is_allowed(event):
    return action_of(event) in ("ALLOWED", "ALLOW")


def is_denied(event):
    action = action_of(event)
    return any(word in action for word in (
        "BLOCK", "DENY", "SUSPICIOUS", "RATE_LIMIT"
    ))


def categories_of(event):
    categories = event.get("categories", [])
    if isinstance(categories, list):
        return ", ".join(str(x) for x in categories) or "NONE"
    return str(categories or "NONE")


def severity_of(event):
    return str(event.get("severity", "UNKNOWN")).upper()


def terminal_width():
    return max(100, min(shutil.get_terminal_size((120, 30)).columns, 180))


def print_header(width):
    print()
    print(CYAN + "=" * width + RESET)
    print(BOLD + CYAN + "SENTINELSHIELD | SECURITY LOG ANALYZER".center(width) + RESET)
    print(CYAN + "=" * width + RESET)


def print_summary(events, invalid_lines, width):
    actions = Counter(action_of(e) for e in events)
    severities = Counter(severity_of(e) for e in events)
    category_counts = Counter()

    for event in events:
        categories = event.get("categories", [])
        if isinstance(categories, list):
            category_counts.update(str(x) for x in categories)
        elif categories:
            category_counts[str(categories)] += 1

    allowed_count = sum(1 for e in events if is_allowed(e))
    denied_count = sum(1 for e in events if is_denied(e))
    suspicious_count = sum(
        1 for e in events if "SUSPICIOUS" in action_of(e)
    )

    print(BOLD + BLUE + "\n[ OVERALL SUMMARY ]" + RESET)
    print(
        f"Total Events: {len(events)} | "
        f"Allowed: {GREEN}{allowed_count}{RESET} | "
        f"Denied/Blocked: {RED}{denied_count}{RESET} | "
        f"Suspicious: {YELLOW}{suspicious_count}{RESET}"
    )
    print(
        f"Severity: HIGH={severities['HIGH']} | "
        f"MEDIUM={severities['MEDIUM']} | "
        f"LOW={severities['LOW']} | "
        f"INFO={severities['INFO']} | "
        f"CRITICAL={severities['CRITICAL']}"
    )

    print(BOLD + BLUE + "\n[ ATTACK CATEGORY SUMMARY ]" + RESET)
    if category_counts:
        for category, count in category_counts.most_common():
            print(f"  {category}: {count}")
    else:
        print("  No attack categories recorded.")

    if invalid_lines:
        print(YELLOW + f"Invalid log lines skipped: {invalid_lines}" + RESET)


def make_card(event, number, card_width):
    timestamp = str(event.get("timestamp", "N/A"))
    timestamp = timestamp.replace("T", " ").replace("+00:00", " UTC")
    ip = str(event.get("source_ip", "N/A"))
    method = str(event.get("method", "N/A"))
    path = str(event.get("path", "N/A"))
    category = categories_of(event)
    severity = severity_of(event)
    action = action_of(event)

    fields = [
        (f"[ LOG {number} ]", BOLD + WHITE),
        (f"Time: {timestamp}", WHITE),
        (f"IP: {ip}", WHITE),
        (f"Request: {method} {path}", WHITE),
        (f"Category: {category}", YELLOW if category != "NONE" else WHITE),
        (
            f"Severity: {severity}",
            RED if severity in ("HIGH", "CRITICAL")
            else YELLOW if severity == "MEDIUM"
            else WHITE
        ),
        (
            f"Action: {action}",
            GREEN if is_allowed(event)
            else RED if is_denied(event)
            else WHITE
        ),
    ]

    lines = []
    inner_width = card_width - 4

    for text, color in fields:
        # Trim long values so each card stays inside its border.
        visible = text[:inner_width]
        lines.append("| " + color + visible.ljust(inner_width) + RESET + " |")

    return lines


def print_event_grid(events, width):
    print()
    print(CYAN + "=" * width + RESET)
    print(BOLD + CYAN + "RECENT SECURITY EVENTS".center(width) + RESET)
    print(CYAN + "=" * width + RESET)

    allowed_events = [e for e in reversed(events) if is_allowed(e)]
    denied_events = [e for e in reversed(events) if is_denied(e)]

    # Prefer 4 allowed and 6 denied events, without inventing records.
    selected = allowed_events[:4] + denied_events[:6]
    selected_ids = {id(e) for e in selected}

    # Fill any remaining slots with other genuine log events.
    if len(selected) < 10:
        for event in reversed(events):
            if id(event) not in selected_ids:
                selected.append(event)
                selected_ids.add(id(event))
            if len(selected) >= 10:
                break

    if not selected:
        print(YELLOW + "No security events found." + RESET)
        return

    columns = 3
    gap = 3
    card_width = max(30, (width - gap * (columns - 1)) // columns)
    cards = [
        make_card(event, index, card_width)
        for index, event in enumerate(selected[:10], start=1)
    ]

    while len(cards) % columns != 0:
        cards.append([
            "| " + " " * (card_width - 4) + " |"
            for _ in range(7)
        ])

    border = "+" + "-" * (card_width - 2) + "+"

    for start in range(0, len(cards), columns):
        row_cards = cards[start:start + columns]
        print(CYAN + border * columns + RESET)

        max_lines = max(len(card) for card in row_cards)

        for line_index in range(max_lines):
            row_parts = []
            for card in row_cards:
                if line_index < len(card):
                    row_parts.append(card[line_index])
                else:
                    row_parts.append("| " + " " * (card_width - 4) + " |")
            print((" " * gap).join(row_parts))

        print(CYAN + border * columns + RESET)


def print_insights(events, width):
    print()
    print(CYAN + "=" * width + RESET)
    print(BOLD + CYAN + "USEFUL SECURITY INSIGHTS".center(width) + RESET)
    print(CYAN + "=" * width + RESET)

    if not events:
        print(YELLOW + "No events available to analyze." + RESET)
        return

    allowed = sum(1 for e in events if is_allowed(e))
    denied = sum(1 for e in events if is_denied(e))
    high_critical = sum(
        1 for e in events if severity_of(e) in ("HIGH", "CRITICAL")
    )

    category_counts = Counter()
    for event in events:
        categories = event.get("categories", [])
        if isinstance(categories, list):
            category_counts.update(str(x) for x in categories)
        elif categories:
            category_counts[str(categories)] += 1

    print(f"  Total recorded events    : {len(events)}")
    print(f"  Allowed requests         : {GREEN}{allowed}{RESET}")
    print(f"  Denied/blocked events    : {RED}{denied}{RESET}")
    print(f"  High/critical events     : {RED}{high_critical}{RESET}")

    if category_counts:
        category, count = category_counts.most_common(1)[0]
        print(f"  Most frequent category   : {category} ({count})")
        print("  Recommendation           : Review repeated attack patterns and source IPs.")
    else:
        print("  Recommendation           : Continue monitoring incoming requests.")

    print(CYAN + "=" * width + RESET)


def main():
    width = terminal_width()
    events, invalid_lines = read_logs()

    print_header(width)
    print_summary(events, invalid_lines, width)
    print_event_grid(events, width)
    print_insights(events, width)


if __name__ == "__main__":
    main()
