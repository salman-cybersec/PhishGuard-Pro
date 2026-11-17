
import os
import re
import secrets
import hashlib
import time
from threading import Lock

from fastapi import Header, HTTPException, Request


MIN_API_KEY_LENGTH = 32
MAX_API_KEY_LENGTH = 256

API_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

ADMIN_SESSION_COOKIE = "phishguard_admin_session"
ADMIN_SESSION_MAX_AGE = 30 * 60

_sessions = {}
_sessions_lock = Lock()


def verify_api_key(
    x_api_key: str | None = Header(default=None),
):
    expected_key = os.getenv("PHISHGUARD_API_KEY")

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured.",
        )

    if (
        len(expected_key) < MIN_API_KEY_LENGTH
        or len(expected_key) > MAX_API_KEY_LENGTH
        or not API_KEY_PATTERN.fullmatch(expected_key)
    ):
        raise HTTPException(
            status_code=503,
            detail="API authentication configuration is invalid.",
        )

    if (
        not isinstance(x_api_key, str)
        or len(x_api_key) != len(expected_key)
        or not secrets.compare_digest(x_api_key, expected_key)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        )

    return True


def _get_admin_password():
    password = os.getenv("PHISHGUARD_ADMIN_PASSWORD")

    if not password or len(password) < 16:
        raise HTTPException(
            status_code=503,
            detail=(
                "Admin authentication is not configured "
                "with a password of at least 16 characters."
            ),
        )

    return password


def verify_admin_credentials(password: str) -> bool:
    expected_password = _get_admin_password()

    if not isinstance(password, str):
        return False

    return secrets.compare_digest(
        password.encode("utf-8"),
        expected_password.encode("utf-8"),
    )


def create_admin_session() -> str:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    now = time.time()

    with _sessions_lock:
        expired = [
            key
            for key, value in _sessions.items()
            if value <= now
        ]

        for key in expired:
            _sessions.pop(key, None)

        _sessions[token_hash] = now + ADMIN_SESSION_MAX_AGE

    return token


def verify_admin_session(request: Request) -> bool:
    token = request.cookies.get(ADMIN_SESSION_COOKIE)

    if not isinstance(token, str) or not token:
        raise HTTPException(
            status_code=401,
            detail="Admin login required.",
        )

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    now = time.time()

    with _sessions_lock:
        expiry = _sessions.get(token_hash)

        if expiry is None or expiry <= now:
            _sessions.pop(token_hash, None)

            raise HTTPException(
                status_code=401,
                detail="Admin session expired. Please log in again.",
            )

    return True


def revoke_admin_session(request: Request) -> None:
    token = request.cookies.get(ADMIN_SESSION_COOKIE)

    if not isinstance(token, str) or not token:
        return

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with _sessions_lock:
        _sessions.pop(token_hash, None)
