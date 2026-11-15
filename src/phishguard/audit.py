
from datetime import datetime, timezone
import json

from phishguard.config import DATA_DIR


AUDIT_FILE = DATA_DIR / "audit.log"


def write_audit_log(action: str, details: dict | None = None):
    if not isinstance(action, str) or not action.strip():
        raise ValueError("Audit action is required.")

    if details is None:
        details = {}

    if not isinstance(details, dict):
        raise ValueError("Audit details must be a dictionary.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action.strip(),
        "details": details,
    }

    with AUDIT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")

    return entry
