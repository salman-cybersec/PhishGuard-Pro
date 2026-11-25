import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.auth import verify_admin_session
from phishguard.email_validation import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[verify_admin_session] = lambda: True
    return TestClient(app)


@pytest.mark.parametrize(
    "path,data",
    [
        ("/admin/email-validator/check", {"email": "test@example.com"}),
        ("/admin/email-validator/bulk", {"emails": "test@example.com"}),
        (
            "/admin/email-validator/export",
            {"category": "Valid", "addresses": "test@example.com"},
        ),
    ],
)
def test_email_validator_rejects_cross_origin_posts(client, path, data):
    response = client.post(
        path,
        headers={"Origin": "https://attacker.example"},
        data=data,
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "path,data",
    [
        ("/admin/email-validator/check", {"email": "test@example.com"}),
        ("/admin/email-validator/bulk", {"emails": "test@example.com"}),
        (
            "/admin/email-validator/export",
            {"category": "Valid", "addresses": "test@example.com"},
        ),
    ],
)
def test_email_validator_rejects_missing_origin_and_referer(client, path, data):
    response = client.post(
        path,
        headers={"Origin": "", "Referer": ""},
        data=data,
    )
    assert response.status_code == 403


def test_email_validator_export_accepts_same_origin(client):
    response = client.post(
        "/admin/email-validator/export",
        headers={"Origin": "http://testserver"},
        data={"category": "Valid", "addresses": "test@example.com"},
    )
    assert response.status_code == 200
    assert "test@example.com" in response.text
