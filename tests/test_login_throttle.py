import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.admin_dashboard import router
from phishguard import login_throttle


@pytest.fixture(autouse=True)
def reset_login_throttle():
    with login_throttle._lock:
        login_throttle._failures.clear()
        login_throttle._last_cleanup = 0.0

    yield

    with login_throttle._lock:
        login_throttle._failures.clear()
        login_throttle._last_cleanup = 0.0


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


@pytest.fixture
def admin_password(monkeypatch):
    password = "Test-Only-Admin-Password-2026!"
    monkeypatch.setenv("PHISHGUARD_ADMIN_PASSWORD", password)
    return password


def test_fifth_failed_login_is_followed_by_temporary_block(
    client,
    admin_password,
):
    for _ in range(5):
        response = client.post(
            "/admin/login",
            data={"password": "Wrong-Password"},
        )
        assert response.status_code == 401

    blocked = client.post(
        "/admin/login",
        data={"password": admin_password},
    )

    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    assert "Too many failed login attempts" in blocked.text


def test_login_block_expires_after_failure_window(
    client,
    admin_password,
    monkeypatch,
):
    clock = [1000.0]
    monkeypatch.setattr(
        login_throttle,
        "monotonic",
        lambda: clock[0],
    )

    for _ in range(5):
        response = client.post(
            "/admin/login",
            data={"password": "Wrong-Password"},
        )
        assert response.status_code == 401

    blocked = client.post(
        "/admin/login",
        data={"password": "Wrong-Password"},
    )
    assert blocked.status_code == 429

    clock[0] += login_throttle.LOGIN_FAILURE_WINDOW_SECONDS + 1

    allowed_again = client.post(
        "/admin/login",
        data={"password": "Wrong-Password"},
    )
    assert allowed_again.status_code == 401


def test_successful_login_clears_previous_failures(
    client,
    admin_password,
):
    for _ in range(4):
        response = client.post(
            "/admin/login",
            data={"password": "Wrong-Password"},
        )
        assert response.status_code == 401

    successful = client.post(
        "/admin/login",
        data={"password": admin_password},
    )
    assert successful.status_code == 303

    for _ in range(5):
        response = client.post(
            "/admin/login",
            data={"password": "Wrong-Password"},
        )
        assert response.status_code == 401

    blocked = client.post(
        "/admin/login",
        data={"password": "Wrong-Password"},
    )
    assert blocked.status_code == 429


def test_missing_admin_password_configuration_does_not_count_as_failure(
    client,
    monkeypatch,
):
    monkeypatch.delenv("PHISHGUARD_ADMIN_PASSWORD", raising=False)

    response = client.post(
        "/admin/login",
        data={"password": "Some-Password"},
    )

    assert response.status_code == 503
    assert not login_throttle._failures
