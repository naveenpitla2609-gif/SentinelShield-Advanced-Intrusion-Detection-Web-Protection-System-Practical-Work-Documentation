import json
import logging
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "Log Analysis"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "security_events.jsonl"

logger = logging.getLogger("sentinelshield")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def log_event(result, source_ip, action):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "method": result["method"],
        "path": result["path"],
        "categories": sorted({
            item["category"]
            for item in result["detections"]
        }),
        "severity": (
            "HIGH" if result["detections"] else "INFO"
        ),
        "action": action,
    }

    logger.info(json.dumps(event, ensure_ascii=True))
    return event
