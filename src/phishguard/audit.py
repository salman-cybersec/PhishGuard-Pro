
from datetime import datetime, timezone
from threading import RLock
import hashlib
import hmac
import json

from phishguard.config import DATA_DIR


AUDIT_FILE = DATA_DIR / "audit.log"
_AUDIT_LOCK = RLock()

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "token",
    "authorization",
    "cookie",
}


def _calculate_hash(entry: dict) -> str:
    content = json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _sanitize_details(value):
    if isinstance(value, dict):
        sanitized = {}

        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Audit detail keys must be strings.")

            if key.lower() in SENSITIVE_KEYS:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_details(item)

        return sanitized

    if isinstance(value, (list, tuple)):
        return [_sanitize_details(item) for item in value]

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    raise ValueError("Audit details contain unsupported data.")


def _verify_audit_log_unlocked() -> bool:
    if not AUDIT_FILE.exists():
        return True

    previous_hash = "GENESIS"

    try:
        lines = AUDIT_FILE.read_text(
            encoding="utf-8"
        ).splitlines()

        for line in lines:
            if not line.strip():
                return False

            entry = json.loads(line)

            if not isinstance(entry, dict):
                return False

            stored_hash = entry.pop("entry_hash", None)

            if not isinstance(stored_hash, str):
                return False

            if entry.get("previous_hash") != previous_hash:
                return False

            calculated_hash = _calculate_hash(entry)

            if not hmac.compare_digest(stored_hash, calculated_hash):
                return False

            previous_hash = stored_hash

        return True

    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return False


def write_audit_log(
    action: str,
    details: dict | None = None,
) -> dict:

    if not isinstance(action, str) or not action.strip():
        raise ValueError("Audit action is required.")

    if len(action) > 100:
        raise ValueError("Audit action is too long.")

    if details is None:
        details = {}

    if not isinstance(details, dict):
        raise ValueError("Audit details must be a dictionary.")

    safe_details = _sanitize_details(details)

    try:
        with _AUDIT_LOCK:
            DATA_DIR.mkdir(parents=True, exist_ok=True)

            if not _verify_audit_log_unlocked():
                raise RuntimeError(
                    "Audit log integrity check failed. "
                    "No new entries were written."
                )

            previous_hash = "GENESIS"

            if AUDIT_FILE.exists():
                lines = AUDIT_FILE.read_text(
                    encoding="utf-8"
                ).splitlines()

                if lines:
                    previous_entry = json.loads(lines[-1])
                    previous_hash = previous_entry["entry_hash"]

            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action.strip(),
                "details": safe_details,
                "previous_hash": previous_hash,
            }

            entry["entry_hash"] = _calculate_hash(entry)

            with AUDIT_FILE.open("a", encoding="utf-8") as file:
                file.write(json.dumps(entry, ensure_ascii=False) + "\n")
                file.flush()

            return entry

    except OSError as error:
        raise RuntimeError("Unable to write audit log.") from error


def verify_audit_log() -> bool:
    with _AUDIT_LOCK:
        return _verify_audit_log_unlocked()
