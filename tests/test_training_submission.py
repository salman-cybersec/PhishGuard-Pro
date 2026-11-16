
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard import database
from phishguard.training_submission import router


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test.db",
    )

    database.initialize_database()

    with database.get_connection() as connection:
        connection.execute(
            """
            INSERT INTO campaigns (name, tracking_code, status)
            VALUES ('Test Campaign', 'TEST123', 'active')
            """
        )

    app = FastAPI()
    app.include_router(router)

    return TestClient(app)


def test_successful_training_submission(client):
    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "John",
        },
    )

    assert response.status_code == 200
    assert "Training submission completed" in response.text

    with database.get_connection() as connection:
        participant = connection.execute(
            "SELECT * FROM participants"
        ).fetchone()

    assert participant["participant_name"] == "John"
    assert participant["consent_ip"] == 0
    assert participant["consent_device"] == 0
    assert participant["ip_address"] is None
    assert participant["user_agent"] is None


def test_invalid_campaign_rejected(client):
    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 999,
            "participant_name": "John",
        },
    )

    assert response.status_code == 404


def test_empty_name_rejected(client):
    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "   ",
        },
    )

    assert response.status_code == 400


def test_invalid_consent_value_rejected(client):
    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "John",
            "consent_ip": "maybe",
        },
    )

    assert response.status_code == 400


def test_inactive_campaign_rejected(client):
    with database.get_connection() as connection:
        connection.execute(
            "UPDATE campaigns SET status = 'paused' WHERE id = 1"
        )

    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "John",
        },
    )

    assert response.status_code == 404
