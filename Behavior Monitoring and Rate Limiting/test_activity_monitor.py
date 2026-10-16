
from activity_monitor import ActivityMonitor

monitor = ActivityMonitor(max_events=3, window_seconds=60)

print("\n" + "=" * 45)
print("     SENTINELSHIELD ACTIVITY MONITOR")
print("=" * 45)

for number in range(1, 6):
    result = monitor.record("192.0.2.10")

    if result["suspicious"]:
        color = "\033[91m"
    else:
        color = "\033[92m"

    reset = "\033[0m"
    print(
        f"{color}Request {number}: {result['status']} "
        f"| Count: {result['event_count']}"
        f"{reset}"
    )

print("=" * 45)

print("\nTEST RESULT: ", end="")
if result["suspicious"] and result["event_count"] == 5:
    print("\033[92mPASS\033[0m")
else:
    print("\033[91mFAIL\033[0m")

print()

