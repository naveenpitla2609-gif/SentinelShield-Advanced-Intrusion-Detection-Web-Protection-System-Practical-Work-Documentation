
import sys
from pathlib import Path

# Allow imports from the SentinelShield project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rule_engine import detect_attacks


RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
MAGENTA = "\033[95m"

WIDTH = 74

ALLOWED_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE"
}


def color(text, shade):
    return f"{shade}{text}{RESET}"


def show_detection_results(value, component="REQUEST BODY"):
    """Print the screenshot-style SentinelShield detection report."""

    findings = detect_attacks(value)

    if component == "HTTP METHOD":
        method = value.strip().upper()

        if method not in ALLOWED_METHODS:
            findings = list(findings)
            findings.append({
                "name": "Unexpected HTTP Method",
                "category": "HTTP_METHOD_ANOMALY",
                "severity": "MEDIUM",
                "evidence": method,
            })

    print()
    print(color("=" * WIDTH, CYAN))
    print(color(
        "SENTINELSHIELD | DETECTION REPORT".center(WIDTH),
        BLUE + BOLD
    ))
    print(color("=" * WIDTH, CYAN))

    print(f"Input inspected : {component} : {value}")
    print(
        "Detection status: "
        + (
            color("THREAT DETECTED", RED + BOLD)
            if findings
            else color("CLEAN", GREEN + BOLD)
        )
    )
    print(f"Rules triggered : {len(findings)}")
    print(color("-" * WIDTH, CYAN))

    if findings:
        for index, finding in enumerate(findings, start=1):
            name = finding.get("name", "Unknown Detection")
            category = finding.get("category", "UNKNOWN")
            severity = finding.get("severity", "UNKNOWN")
            evidence = finding.get("evidence", value)

            print()
            print(color(f"[ Finding {index} ]", WHITE + BOLD))
            print(
                f"Attack name      : "
                f"{color(name, GREEN + BOLD)}"
            )
            print(f"Category         : {category}")

            severity_color = (
                RED + BOLD
                if severity.upper() in {"HIGH", "CRITICAL"}
                else YELLOW + BOLD
            )
            print(
                f"Severity         : "
                f"{color(severity, severity_color)}"
            )
            print(
                f"Matched evidence : "
                f"{color(str(evidence), YELLOW)}"
            )
            print(
                f"Recommended      : "
                f"{color('Block or investigate request', WHITE)}"
            )
    else:
        print()
        print(color(
            "No configured attack signatures matched.",
            GREEN
        ))
        print(
            f"Recommended      : "
            f"{color('Allow request; continue monitoring', GREEN)}"
        )

    print()
    print(color("=" * WIDTH, CYAN))
    print(color(
        "END OF SECURITY REPORT".center(WIDTH),
        BLUE + BOLD
    ))
    print(color("=" * WIDTH, CYAN))
    print()


def choose_component():
    print()
    print(color("SENTINELSHIELD | COMPONENT TESTER", CYAN + BOLD))
    print(color("-" * 40, CYAN))
    print("1. URL Path")
    print("2. HTTP Method")
    print("3. Query Parameters")
    print("4. HTTP Headers")
    print("5. Form Data")
    print("6. Request Body")
    print("0. Exit")

    return input("\nSelect component: ").strip()


def run_component_test(choice):
    component_map = {
        "1": ("URL PATH", "Enter URL path to inspect: "),
        "2": ("HTTP METHOD", "Enter HTTP method to inspect: "),
        "3": ("QUERY PARAMETERS", "Enter query parameter value: "),
        "4": ("HEADERS", "Enter header value to inspect: "),
        "5": ("FORM DATA", "Enter form data value: "),
        "6": ("REQUEST BODY", "Enter request body to inspect: "),
    }

    if choice not in component_map:
        print(color("Invalid selection. Choose 0â€“6.", RED))
        return

    component, prompt = component_map[choice]
    value = input(prompt).strip()

    if not value:
        print(color("Input cannot be empty.", YELLOW))
        return

    show_detection_results(value, component)


def main():
    while True:
        choice = choose_component()

        if choice == "0":
            print(color("SentinelShield tester closed.", CYAN))
            break

        run_component_test(choice)


if __name__ == "__main__":
    main()

