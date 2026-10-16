
import json
import os
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "security_events.jsonl")

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"


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


def get_categories(event):
    categories = event.get("categories", [])

    if isinstance(categories, list):
        return [str(category).upper() for category in categories]

    if categories:
        return [str(categories).upper()]

    return []


def main():
    events, invalid_lines, file_found = read_events()

    print()
    print(CYAN + "=" * 78 + RESET)
    print(BOLD + CYAN + "SENTINELSHIELD | HTTP METHOD ANOMALY REPORT" + RESET)
    print(CYAN + "=" * 78 + RESET)

    if not file_found:
        print(RED + f"ERROR: Log file not found: {LOG_FILE}" + RESET)
        return

    # Use recorded detection categories, not assumptions about methods.
    anomalies = [
        event for event in events
        if "HTTP_METHOD_ANOMALY" in get_categories(event)
    ]

    method_counts = Counter(
        str(event.get("method", "UNKNOWN")).upper()
        for event in anomalies
    )

    severity_counts = Counter(
        str(event.get("severity", "UNKNOWN")).upper()
        for event in anomalies
    )

    action_counts = Counter(
        str(event.get("action", "UNKNOWN")).upper()
        for event in anomalies
    )

    print(f"\nTotal security events      : {len(events)}")
    print(f"HTTP method anomaly events  : {len(anomalies)}")
    print(f"Invalid log lines skipped  : {invalid_lines}")
    print(f"Methods involved           : {len(method_counts)}")

    print("\n" + BOLD + "ANOMALOUS HTTP METHODS" + RESET)
    print("-" * 78)
    print(f"{'METHOD':<20}{'EVENT COUNT':>15}")
    print("-" * 78)

    if method_counts:
        for method, count in method_counts.most_common():
            print(f"{method:<20}{count:>15}")
    else:
        print(GREEN + "No HTTP method anomalies found in saved logs." + RESET)

    print("\n" + BOLD + "SEVERITY BREAKDOWN" + RESET)
    print("-" * 78)

    if severity_counts:
        for severity, count in severity_counts.most_common():
            color = RED if severity in ("HIGH", "CRITICAL") else YELLOW
            print(f"{color}{severity:<20}{count:>15}{RESET}")
    else:
        print("No anomaly severity records.")

    print("\n" + BOLD + "ACTION BREAKDOWN" + RESET)
    print("-" * 78)

    if action_counts:
        for action, count in action_counts.most_common():
            color = GREEN if action == "ALLOWED" else RED
            print(f"{color}{action:<30}{count:>10}{RESET}")
    else:
        print("No anomaly actions recorded.")

    print("\n" + BOLD + "LATEST 10 METHOD ANOMALIES" + RESET)
    print("-" * 78)

    if anomalies:
        for event in reversed(anomalies[-10:]):
            timestamp = str(event.get("timestamp", "N/A"))
            source_ip = str(event.get("source_ip", "N/A"))
            method = str(event.get("method", "N/A"))
            path = str(event.get("path", "N/A"))
            severity = str(event.get("severity", "UNKNOWN"))
            action = str(event.get("action", "UNKNOWN"))
            categories = ", ".join(get_categories(event)) or "NONE"

            print(f"\nTime     : {timestamp}")
            print(f"Source IP: {source_ip}")
            print(f"Method   : {method}")
            print(f"Path     : {path}")
            print(f"Category : {categories}")
            print(f"Severity : {severity}")
            print(f"Action   : {RED}{action}{RESET}")
    else:
        print("No matching events to display.")

    print("\n" + CYAN + "=" * 78 + RESET)
    print(BOLD + WHITE + "HTTP METHOD ANALYSIS COMPLETE" + RESET)
    print(CYAN + "=" * 78 + RESET)

    print(
        YELLOW
        + "\nNote: This report analyzes recorded events only. "
        "It does not send HTTP requests or perform live detection."
        + RESET
    )


if __name__ == "__main__":
    main()
