#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]] || [[ ! -f .env ]]; then
    echo "First-time setup required..."
    ./setup.sh
fi

echo "Starting PhishGuard Pro..."
exec .venv/bin/python main.py
