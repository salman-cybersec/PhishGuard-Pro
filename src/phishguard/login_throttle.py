"""In-memory rate limiting for failed administrator login attempts."""

from collections import deque
from math import ceil
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request


MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
CLEANUP_INTERVAL_SECONDS = 60

_failures = {}
_lock = Lock()
_last_cleanup = 0.0


def _client_ip(request: Request) -> str:
    """Use the ASGI client address; do not trust forwarded headers."""
    return request.client.host if request.client else "unknown"


def _cleanup_expired(now: float) -> None:
    global _last_cleanup

    if now - _last_cleanup < CLEANUP_INTERVAL_SECONDS:
        return

    for ip, attempts in list(_failures.items()):
        while (
            attempts
            and now - attempts[0] >= LOGIN_FAILURE_WINDOW_SECONDS
        ):
            attempts.popleft()

        if not attempts:
            _failures.pop(ip, None)

    _last_cleanup = now


def check_login_allowed(request: Request) -> None:
    """Reject login attempts when the IP has reached its failure limit."""
    now = monotonic()
    ip = _client_ip(request)

    with _lock:
        _cleanup_expired(now)

        attempts = _failures.get(ip)

        if not attempts:
            return

        while (
            attempts
            and now - attempts[0] >= LOGIN_FAILURE_WINDOW_SECONDS
        ):
            attempts.popleft()

        if not attempts:
            _failures.pop(ip, None)
            return

        if len(attempts) >= MAX_FAILED_LOGIN_ATTEMPTS:
            retry_after = max(
                1,
                ceil(
                    LOGIN_FAILURE_WINDOW_SECONDS
                    - (now - attempts[0])
                ),
            )

            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )


def record_login_failure(request: Request) -> None:
    """Record one incorrect administrator password attempt."""
    now = monotonic()
    ip = _client_ip(request)

    with _lock:
        _cleanup_expired(now)
        attempts = _failures.setdefault(ip, deque())

        while (
            attempts
            and now - attempts[0] >= LOGIN_FAILURE_WINDOW_SECONDS
        ):
            attempts.popleft()

        attempts.append(now)


def clear_login_failures(request: Request) -> None:
    """Clear failed attempts after successful authentication."""
    ip = _client_ip(request)

    with _lock:
        _failures.pop(ip, None)
