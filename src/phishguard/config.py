
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
REPORT_DIR = PROJECT_ROOT / "reports"

APP_NAME = "PhishGuard Pro"
APP_VERSION = "0.1.0"
DEVELOPER = "Salman Afzal"


def _get_port(name: str, default: int) -> int:
    value = os.getenv(name, str(default))

    try:
        port = int(value)
    except ValueError as error:
        raise ValueError(
            f"{name} must be a valid integer."
        ) from error

    if not 1 <= port <= 65535:
        raise ValueError(
            f"{name} must be between 1 and 65535."
        )

    return port


def _get_boolean(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in {"true", "1", "yes", "on"}:
        return True

    if normalized in {"false", "0", "no", "off"}:
        return False

    raise ValueError(
        f"{name} must be true or false."
    )


APP_HOST = os.getenv(
    "PHISHGUARD_HOST",
    "127.0.0.1",
).strip()

if not APP_HOST:
    raise ValueError("PHISHGUARD_HOST cannot be empty.")

APP_PORT = _get_port("PHISHGUARD_PORT", 3399)

DEBUG = _get_boolean("PHISHGUARD_DEBUG", False)

MAX_REQUEST_SIZE = 1_000_000
RATE_LIMIT_PER_MINUTE = 60

ALLOWED_EVENT_TYPES = {
    "page_visit",
    "training_page_view",
    "form_interaction",
    "simulation_complete",
}
