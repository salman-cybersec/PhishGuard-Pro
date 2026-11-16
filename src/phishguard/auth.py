
import os
import re
import secrets

from fastapi import Header, HTTPException


MIN_API_KEY_LENGTH = 32
MAX_API_KEY_LENGTH = 256

API_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


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
