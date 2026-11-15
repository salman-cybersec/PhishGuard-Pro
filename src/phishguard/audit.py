
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from phishguard.config import DATA_DIR


AUDIT_FILE = DATA_DIR / "audit.log"


def _calculate_hash(entry: dict) -> str:
    content = json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def write_audit_log(action: str, details: dict | None = None):
    if not isinstance(action, str) or not action.strip():
        raise ValueError("Audit action is required.")

    if details is None:
        details = {}

    if not isinstance(details, dict):
        raise ValueError("Audit details must be a dictionary.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    previous_hash = "GENESIS"

    if AUDIT_FILE.exists():
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        if lines:
            previous_entry = json.loads(lines[-1])
            previous_hash = previous_entry.get("entry_hash", "INVALID")

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action.strip(),
        "details": details,
        "previous_hash": previous_hash,
    }

    entry["entry_hash"] = _calculate_hash(entry)

    with AUDIT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")

    return entry


def verify_audit_log() -> bool:
    if not AUDIT_FILE.exists():
        return True

    previous_hash = "GENESIS"

    try:
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()

        for line in lines:
            if not line.strip():
                continue

            entry = json.loads(line)
            stored_hash = entry.pop("entry_hash", None)

            if entry.get("previous_hash") != previous_hash:
                return False

            calculated_hash = _calculate_hash(entry)

            if stored_hash != calculated_hash:
                return False

            previous_hash = stored_hash

        return True

    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return False
