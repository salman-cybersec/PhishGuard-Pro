import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
REPORT_DIR = PROJECT_ROOT / "reports"

APP_NAME = "PhishGuard Pro"
APP_VERSION = "0.1.0"
DEVELOPER = "Salman Afzal"

APP_HOST = os.getenv("PHISHGUARD_HOST", "127.0.0.1")
APP_PORT = int(os.getenv("PHISHGUARD_PORT", "3399"))

DEBUG = os.getenv("PHISHGUARD_DEBUG", "false").lower() == "true"

MAX_REQUEST_SIZE = 1_000_000
RATE_LIMIT_PER_MINUTE = 60

ALLOWED_EVENT_TYPES = {
    "page_visit",
    "training_page_view",
    "form_interaction",
    "simulation_complete",
}
