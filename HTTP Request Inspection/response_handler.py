from datetime import datetime


class ResponseHandler:
    """Select and record a response to a security event."""

    VALID_ACTIONS = {"ALLOW", "ALERT", "BLOCK"}

    def handle(self, action, source_ip="unknown", reason="No reason provided"):
        action = str(action).strip().upper()

        if action not in self.VALID_ACTIONS:
            raise ValueError(
                f"Unsupported action: {action}. "
                f"Choose one of {sorted(self.VALID_ACTIONS)}."
            )

        result = {
            "timestamp": datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
            "action": action,
            "source_ip": str(source_ip),
            "reason": str(reason),
        }

        messages = {
            "ALLOW": "Request permitted",
            "ALERT": "Suspicious activity flagged for review",
            "BLOCK": "Block decision recorded",
        }

        result["message"] = messages[action]
        return result
