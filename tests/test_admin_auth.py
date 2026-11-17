
import pytest

from fastapi import FastAPI, Depends, Request
from fastapi.testclient import TestClient

from phishguard.auth import (
    ADMIN_SESSION_COOKIE,
    _sessions,
    _sessions_lock,
    verify_api_key,
    verify_admin_credentials,
    create_admin_session,
    verify_admin_session,
    revoke_admin_session,
)


@pytest.fixture(autouse=True)
def clean_sessions():
    with _sessions_lock:
        _sessions.clear()

    yield

    with _sessions_lock:
        _sessions.clear()


def test_admin_password_accepts_correct_password(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ADMIN_PASSWORD",
        "A-Strong-Test-Password-2026!",
    )

    assert verify_admin_credentials(
        "A-Strong-Test-Password-2026!"
    )


def test_admin_password_rejects_incorrect_password(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ADMIN_PASSWORD",
        "A-Strong-Test-Password-2026!",
    )

    assert not verify_admin_credentials("Wrong-Password")


def test_admin_password_requires_configuration(monkeypatch):
    monkeypatch.delenv(
        "PHISHGUARD_ADMIN_PASSWORD",
        raising=False,
    )

    with pytest.raises(Exception):
        verify_admin_credentials("Any-Test-Password")


def test_admin_password_rejects_short_configuration(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ADMIN_PASSWORD",
        "short",
    )

    with pytest.raises(Exception):
        verify_admin_credentials("short")


def test_admin_session_is_created_and_verified():
    app = FastAPI()

    @app.get("/protected")
    def protected(
        authenticated: bool = Depends(verify_admin_session),
    ):
        return {"authenticated": authenticated}

    client = TestClient(app)

    token = create_admin_session()
    client.cookies.set(ADMIN_SESSION_COOKIE, token)

    response = client.get("/protected")

    assert response.status_code == 200
    assert response.json()["authenticated"] is True


def test_admin_session_rejects_missing_cookie():
    app = FastAPI()

    @app.get("/protected")
    def protected(
        authenticated: bool = Depends(verify_admin_session),
    ):
        return {"authenticated": authenticated}

    client = TestClient(app)

    response = client.get("/protected")

    assert response.status_code == 401


def test_revoked_admin_session_is_rejected():
    app = FastAPI()

    @app.get("/protected")
    def protected(
        authenticated: bool = Depends(verify_admin_session),
    ):
        return {"authenticated": authenticated}

    @app.post("/logout")
    def logout(request: Request):
        revoke_admin_session(request)
        return {"revoked": True}

    client = TestClient(app)

    token = create_admin_session()
    client.cookies.set(ADMIN_SESSION_COOKIE, token)

    logout_response = client.post("/logout")

    assert logout_response.status_code == 200

    response = client.get("/protected")

    assert response.status_code == 401


def test_api_key_accepts_correct_key(monkeypatch):
    api_key = "A" * 40

    monkeypatch.setenv("PHISHGUARD_API_KEY", api_key)

    assert verify_api_key(x_api_key=api_key) is True


def test_api_key_rejects_incorrect_key(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_API_KEY", "A" * 40)

    with pytest.raises(Exception):
        verify_api_key(x_api_key="B" * 40)
