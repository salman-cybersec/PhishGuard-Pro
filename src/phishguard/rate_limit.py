from collections import deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request

from phishguard.config import RATE_LIMIT_PER_MINUTE


_requests = {}
_lock = Lock()

WINDOW_SECONDS = 60
CLEANUP_INTERVAL = 60
_last_cleanup = 0.0


def enforce_rate_limit(request: Request):
    global _last_cleanup

    client_ip = request.client.host if request.client else "unknown"
    current_time = monotonic()

    with _lock:
        # Periodically remove expired entries belonging to inactive IPs.
        if current_time - _last_cleanup >= CLEANUP_INTERVAL:
            for ip, entries in list(_requests.items()):
                while (
                    entries
                    and current_time - entries[0] >= WINDOW_SECONDS
                ):
                    entries.popleft()

                if not entries:
                    _requests.pop(ip, None)

            _last_cleanup = current_time

        timestamps = _requests.get(client_ip)

        if timestamps is None:
            timestamps = deque()
            _requests[client_ip] = timestamps

        # Clean the current IP's window even between global cleanup runs.
        while (
            timestamps
            and current_time - timestamps[0] >= WINDOW_SECONDS
        ):
            timestamps.popleft()

        if len(timestamps) >= RATE_LIMIT_PER_MINUTE:
            if not timestamps:
                _requests.pop(client_ip, None)

            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later.",
            )

        timestamps.append(current_time)

    return True
