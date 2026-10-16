
import os
import sys

# Allow imports from the project root.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from app import app
except Exception as exc:
    print("\nERROR: Could not load SentinelShield configuration.")
    print(f"Details: {exc}")
    raise SystemExit(1)


RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"


def main():
    config = app.config
    limit = config.get("RATE_LIMIT_REQUESTS", 30)
    window = config.get("RATE_LIMIT_WINDOW_SECONDS", 60)

    print()
    print(CYAN + "=" * 60 + RESET)
    print(BOLD + CYAN + "SENTINELSHIELD | RATE LIMITING REPORT" + RESET)
    print(CYAN + "=" * 60 + RESET)

    print(f"{BOLD}Protection Status : {GREEN}CONFIGURED{RESET}")
    print(f"{BOLD}Request Limit     : {WHITE}{limit} requests{RESET}")
    print(f"{BOLD}Time Window       : {WHITE}{window} seconds{RESET}")
    print(f"{BOLD}Endpoint          : {WHITE}/inspect{RESET}")
    print(f"{BOLD}Limit Response    : {YELLOW}HTTP 429{RESET}")

    print("\n" + CYAN + "-" * 60 + RESET)
    print(BOLD + "HOW IT WORKS" + RESET)
    print("1. Requests are tracked by client IP.")
    print("2. Requests within the configured limit are allowed.")
    print("3. Requests exceeding the limit receive HTTP 429.")
    print("4. /health is excluded from rate limiting in this project.")
    print(CYAN + "-" * 60 + RESET)

    print(
        YELLOW
        + "\nNote: This report displays configured settings; "
        "it does not claim live blocked-request counts."
        + RESET
    )
    print(CYAN + "=" * 60 + RESET)


if __name__ == "__main__":
    main()
