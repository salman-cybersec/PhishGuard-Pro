#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "======================================"
echo "       PHISHGUARD PRO SETUP"
echo "======================================"

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: Python 3 is required."
    exit 1
}

python3 - <<'CHECK'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("ERROR: Python 3.10 or newer is required.")
print("Python version:", sys.version.split()[0])
CHECK

if [[ ! -x .venv/bin/python ]]; then
    echo "[1/5] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/5] Existing virtual environment found."
fi

echo "[2/5] Updating pip..."
.venv/bin/python -m pip install --upgrade pip

echo "[3/5] Installing project dependencies..."
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .

mkdir -p data reports
chmod 700 data reports

if [[ ! -f .env ]]; then
    echo "[4/5] Creating private machine configuration..."
    .venv/bin/python - <<'GENERATE'
import os
import secrets
from pathlib import Path

template = Path(".env.example").read_text()
api_key = secrets.token_urlsafe(48)
admin_password = secrets.token_urlsafe(24)

content = template.replace(
    "replace-with-a-long-random-secret", api_key
).replace(
    "replace-with-a-unique-strong-password", admin_password
)

fd = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as file:
    file.write(content)

os.chmod(".env", 0o600)

print()
print("NEW ADMIN PASSWORD (save this securely):")
print(admin_password)
print()
print("A unique API key has also been generated and saved in .env.")
GENERATE
else
    echo "[4/5] Existing .env found; preserving it."
    chmod 600 .env
fi

echo "[5/5] Setup completed."
echo "Database tables will initialize when the application starts."
echo "Run the application with: ./run.sh"
