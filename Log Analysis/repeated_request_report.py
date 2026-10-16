
import json
import os
from collections import Counter, defaultdict

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
    invalid = 0

    if not os.path.isfile(LOG_FILE):
        return events, invalid, False

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    events.append(item)
                else:
                    invalid += 1
            except json.JSONDecodeError:
                invalid += 1

    return events, invalid, True


def main():
    events, invalid, found = read_events()

    print()
    print(CYAN + "=" * 76 + RESET)
    print(BOLD + CYAN + "SENTINELSHIELD | REPEATED REQUEST MONITOR" + RESET)
    print(CYAN + "=" * 76 + RESET)

    if not found:
        print(RED + f"Log file not found: {LOG_FILE}" + RESET)
        return

    # Count actual requests by source IP from the saved event log.
    ip_counts = Counter()
    suspicious_ips = Counter()
    repeated_events = 0
    action_counts = Counter()

    for event in events:
        ip = str(event.get("source_ip", "UNKNOWN"))
        ip_counts[ip] += 1

        action = str(event.get("action", "UNKNOWN")).upper()
        action_counts[action] += 1

        categories = event.get("categories", [])
        if not isinstance(categories, list):
            categories = [str(categories)] if categories else []

        if "REPEATED_REQUESTS" in categories:
            repeated_events += 1
            suspicious_ips[ip] += 1

    repeated_ips = {
        ip: count for ip, count in ip_counts.items() if count > 1
    }

    print(f"\nTotal logged events       : {len(events)}")
    print(f"Unique source IPs         : {len(ip_counts)}")
    print(f"IPs with multiple events  : {len(repeated_ips)}")
    print(f"Repeated-request events   : {repeated_events}")
    print(f"Invalid lines skipped     : {invalid}")

    print("\n" + BOLD + "SOURCE IP ACTIVITY" + RESET)
    print("-" * 76)
    print(f"{'SOURCE IP':<24} {'TOTAL EVENTS':>14} {'REPEAT ALERTS':>16}")
    print("-" * 76)

    if ip_counts:
        for ip, count in ip_counts.most_common(15):
            alerts = suspicious_ips[ip]
            color = RED if alerts else GREEN
            print(
                f"{ip[:23]:<24} {count:>14} "
                f"{color}{alerts:>16}{RESET}"
            )
    else:
        print("No request events recorded.")

    print("\n" + BOLD + "RECENT REPEATED-REQUEST EVENTS" + RESET)
    print("-" * 76)

    matches = [
        event for event in events
        if "REPEATED_REQUESTS" in (
            event.get("categories", [])
            if isinstance(event.get("categories", []), list)
            else [event.get("categories")]
        )
    ]

    if not matches:
        print(GREEN + "No repeated-request events found in saved logs." + RESET)
    else:
        for event in reversed(matches[-10:]):
            timestamp = str(event.get("timestamp", "N/A"))
            ip = str(event.get("source_ip", "UNKNOWN"))
            method = str(event.get("method", "N/A"))
            path = str(event.get("path", "N/A"))
            severity = str(event.get("severity", "UNKNOWN"))
            action = str(event.get("action", "UNKNOWN"))

            print(
                f"{timestamp} | IP={ip} | {method} {path} | "
                f"{severity} | {RED}{action}{RESET}"
            )

    print("\n" + CYAN + "=" * 76 + RESET)
    print(BOLD + WHITE + "REPEATED REQUEST ANALYSIS COMPLETE" + RESET)
    print(CYAN + "=" * 76 + RESET)

    print(
        YELLOW
        + "\nNote: IP totals are counts of saved log events, not all live HTTP "
        "requests. Historical events may span different time windows."
        + RESET
    )


if __name__ == "__main__":
    main()
