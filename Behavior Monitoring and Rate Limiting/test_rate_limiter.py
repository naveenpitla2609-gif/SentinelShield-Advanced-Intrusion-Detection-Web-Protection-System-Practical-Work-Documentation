
from rate_limiter import RateLimiter


# ANSI terminal colors
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"


def main():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    results = [limiter.check("test-ip") for _ in range(3)]

    print()
    print(CYAN + BOLD + "=" * 54 + RESET)
    print(CYAN + BOLD + "       SENTINELSHIELD SECURITY VALIDATION" + RESET)
    print(CYAN + BOLD + "              RATE LIMITER TEST" + RESET)
    print(CYAN + BOLD + "=" * 54 + RESET)

    for number, result in enumerate(results, start=1):
        if result["allowed"]:
            status = GREEN + BOLD + "ALLOWED" + RESET
        else:
            status = RED + BOLD + "BLOCKED" + RESET

        print(f"\n{WHITE}{BOLD}[REQUEST {number}]{RESET} {status}")
        print(f"  Request Limit : {result['limit']}")
        print(f"  Remaining     : {result['remaining']}")

        if not result["allowed"]:
            print(
                f"  {YELLOW}Retry After   : "
                f"{result['retry_after']} seconds{RESET}"
            )

    passed = (
        results[0]["allowed"]
        and results[1]["allowed"]
        and not results[2]["allowed"]
    )

    print("\n" + CYAN + "=" * 54 + RESET)

    if passed:
        print(
            GREEN + BOLD
            + "  VALIDATION RESULT: PASS"
            + RESET
        )
        print(GREEN + "  Rate limiter is working correctly." + RESET)
    else:
        print(RED + BOLD + "  VALIDATION RESULT: FAIL" + RESET)

    print(CYAN + "=" * 54 + RESET + "\n")


if __name__ == "__main__":
    main()

