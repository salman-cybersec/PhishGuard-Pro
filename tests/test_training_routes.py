
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard import database
from phishguard.training_submission import router as submission_router
from phishguard.training_routes import router as training_page_router


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_database_path = tmp_path / "test_phishguard.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        test_database_path,
    )

    database.initialize_database()

    with database.get_connection() as connection:
        connection.execute(
            """
            INSERT INTO campaigns (
                name,
                tracking_code,
                status
            )
            VALUES (?, ?, ?)
            """,
            (
                "Security Awareness Test",
                "TEST123",
                "active",
            ),
        )

    app = FastAPI()
    app.include_router(submission_router)
    app.include_router(training_page_router)

    return TestClient(app)


def test_training_submit_endpoint_saves_participant(client):
    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "Test Participant",
        },
    )

    assert response.status_code == 200

    with database.get_connection() as connection:
        participant = connection.execute(
            """
            SELECT participant_name, campaign_id
            FROM participants
            WHERE participant_name = ?
            """,
            ("Test Participant",),
        ).fetchone()

    assert participant is not None
    assert participant["participant_name"] == "Test Participant"
    assert participant["campaign_id"] == 1


def test_active_campaign_training_page(client):
    response = client.get(
        "/training/1",
        params={
            "service_id": "facebook",
            "scenario_id": "account_security",
        },
    )

    assert response.status_code == 200
    assert "Facebook" in response.text
    assert "Account Security Awareness" in response.text


def test_missing_campaign_returns_404(client):
    response = client.get("/training/999")

    assert response.status_code == 404


def test_invalid_scenario_returns_400(client):
    response = client.get(
        "/training/1",
        params={
            "service_id": "facebook",
            "scenario_id": "invalid_scenario",
        },
    )

    assert response.status_code == 400


def test_invalid_campaign_id_is_rejected(client):
    response = client.get("/training/0")

    assert response.status_code == 400


def test_training_page_has_no_password_field(client):
    response = client.get("/training/1")

    assert response.status_code == 200
    assert 'type="password"' not in response.text
    assert 'name="password"' not in response.text


def test_submission_without_consent_does_not_collect_ip_or_device(client):
    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "Privacy Test Participant",
        },
        headers={
            "user-agent": "PhishGuard-Test-Browser",
        },
    )

    assert response.status_code == 200

    with database.get_connection() as connection:
        participant = connection.execute(
            """
            SELECT
                consent_ip,
                ip_address,
                consent_device,
                user_agent,
                browser_name,
                os_name,
                device_type
            FROM participants
            WHERE participant_name = ?
            """,
            ("Privacy Test Participant",),
        ).fetchone()

    assert participant is not None
    assert participant["consent_ip"] == 0
    assert participant["ip_address"] is None
    assert participant["consent_device"] == 0
    assert participant["user_agent"] is None
    assert participant["browser_name"] is None
    assert participant["os_name"] is None
    assert participant["device_type"] is None
