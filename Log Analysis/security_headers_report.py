
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from app import app
except Exception as exc:
    print(f"ERROR: Could not load Flask app: {exc}")
    raise SystemExit(1)


RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"


def main():
    expected_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
    }

    print()
    print(CYAN + "=" * 68 + RESET)
    print(BOLD + CYAN + "SENTINELSHIELD | SECURITY HEADERS REPORT" + RESET)
    print(CYAN + "=" * 68 + RESET)

    # Make a real in-process request to the Flask application.
    try:
        with app.test_client() as client:
            response = client.get("/health")
    except Exception as exc:
        print(RED + f"ERROR: Health endpoint check failed: {exc}" + RESET)
        raise SystemExit(1)

    print(f"\nEndpoint: /health")
    print(f"HTTP Status: {response.status_code}")
    print("\n" + BOLD + "HEADER VALIDATION" + RESET)
    print("-" * 68)

    passed = 0

    for header, expected_value in expected_headers.items():
        actual_value = response.headers.get(header)

        if actual_value == expected_value:
            status = GREEN + "PASS" + RESET
            passed += 1
        elif actual_value is None:
            status = RED + "MISSING" + RESET
        else:
            status = YELLOW + "CHECK" + RESET

        print(f"{header:<28} Expected: {expected_value:<12} {status}")
        print(f"{'':28} Actual:   {actual_value or 'Not present'}")

    print("-" * 68)
    print(f"Headers passed: {passed}/{len(expected_headers)}")

    if passed == len(expected_headers):
        print(GREEN + BOLD + "RESULT: All configured headers verified." + RESET)
    else:
        print(YELLOW + BOLD + "RESULT: Review missing or mismatched headers." + RESET)

    print(CYAN + "=" * 68 + RESET)


if __name__ == "__main__":
    main()
