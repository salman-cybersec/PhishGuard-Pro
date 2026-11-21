import pytest

from fastapi.testclient import TestClient

from phishguard.server import app
from phishguard import rate_limit


@pytest.fixture
def client(monkeypatch):
    rate_limit._requests.clear()
    monkeypatch.setattr(rate_limit, "RATE_LIMIT_PER_MINUTE", 2)

    test_client = TestClient(app, raise_server_exceptions=False)
    yield test_client

    test_client.close()
    rate_limit._requests.clear()


def test_rate_limit_returns_429_after_limit(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/openapi.json").status_code == 200

    response = client.get("/openapi.json")

    assert response.status_code == 429
    assert response.json()["detail"] == (
        "Too many requests. Please try again later."
    )


def test_health_endpoint_is_exempt_from_rate_limit(client):
    client.get("/openapi.json")
    client.get("/openapi.json")

    response = client.get("/health")

    assert response.status_code == 200


def test_security_headers_are_present(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"


def test_rate_limiter_removes_inactive_ip_entries(monkeypatch):
    from starlette.requests import Request

    fake_time = [100.0]
    monkeypatch.setattr(rate_limit, "monotonic", lambda: fake_time[0])

    def make_request(ip):
        return Request({
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": (ip, 12345),
            "server": ("testserver", 80),
        })

    rate_limit._requests.clear()
    rate_limit._last_cleanup = 0.0

    rate_limit.enforce_rate_limit(make_request("192.0.2.10"))
    assert "192.0.2.10" in rate_limit._requests

    # More than one cleanup interval later, the old IP should be removed.
    fake_time[0] = 161.0
    rate_limit.enforce_rate_limit(make_request("192.0.2.20"))

    assert "192.0.2.10" not in rate_limit._requests
    assert "192.0.2.20" in rate_limit._requests


def test_rate_limiter_preserves_active_ip_entries(monkeypatch):
    from starlette.requests import Request

    fake_time = [100.0]
    monkeypatch.setattr(rate_limit, "monotonic", lambda: fake_time[0])

    request = Request({
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "client": ("192.0.2.30", 12345),
        "server": ("testserver", 80),
    })

    rate_limit._requests.clear()
    rate_limit._last_cleanup = 0.0

    rate_limit.enforce_rate_limit(request)

    fake_time[0] = 130.0
    rate_limit.enforce_rate_limit(request)

    assert len(rate_limit._requests["192.0.2.30"]) == 2
