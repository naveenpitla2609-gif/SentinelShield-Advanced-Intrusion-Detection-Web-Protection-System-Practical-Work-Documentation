
import logging


class SentinelShieldFormatter(logging.Formatter):
    """Color-coded console output for SentinelShield."""

    RESET = "\033[0m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"

    def format(self, record):
        message = super().format(record)

        if record.levelno >= logging.ERROR:
            color = self.RED
        elif record.levelno >= logging.WARNING:
            color = self.YELLOW
        elif record.levelno >= logging.INFO:
            color = self.GREEN
        else:
            color = self.CYAN

        return f"{color}{self.BOLD}{message}{self.RESET}"


def setup_console_logger():
    logger = logging.getLogger("sentinelshield.console")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            SentinelShieldFormatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        logger.addHandler(handler)

    return logger
