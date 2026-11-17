
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.admin_dashboard import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def admin_password(monkeypatch):
    password = "Test-Only-Admin-Password-2026!"
    monkeypatch.setenv("PHISHGUARD_ADMIN_PASSWORD", password)
    return password


def test_admin_login_page_is_available(client):
    response = client.get("/admin/login")

    assert response.status_code == 200
    assert "password" in response.text.lower()


def test_dashboard_requires_login(client):
    response = client.get("/admin/dashboard")

    assert response.status_code == 401


def test_invalid_admin_password_is_rejected(
    client,
    admin_password,
):
    response = client.post(
        "/admin/login",
        data={"password": "Incorrect-Password"},
    )

    assert response.status_code in (401, 403)


def test_valid_admin_login_creates_session(
    client,
    admin_password,
):
    response = client.post(
        "/admin/login",
        data={"password": admin_password},
    )

    assert response.status_code in (302, 303)
    assert response.headers["location"].endswith(
        "/admin/dashboard"
    )
    assert "phishguard_admin_session" in response.cookies


def test_logout_clears_admin_session(
    client,
    admin_password,
):
    login_response = client.post(
        "/admin/login",
        data={"password": admin_password},
    )

    assert login_response.status_code in (302, 303)

    logout_response = client.post("/admin/logout")

    assert logout_response.status_code in (302, 303, 200)

    dashboard_response = client.get("/admin/dashboard")

    assert dashboard_response.status_code == 401
