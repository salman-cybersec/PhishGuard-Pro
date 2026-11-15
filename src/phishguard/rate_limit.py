
from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request

from phishguard.config import RATE_LIMIT_PER_MINUTE


_requests = defaultdict(deque)
_lock = Lock()


def enforce_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    current_time = monotonic()
    window_seconds = 60

    with _lock:
        timestamps = _requests[client_ip]

        while timestamps and current_time - timestamps[0] >= window_seconds:
            timestamps.popleft()

        if len(timestamps) >= RATE_LIMIT_PER_MINUTE:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later.",
            )

        timestamps.append(current_time)

    return True
