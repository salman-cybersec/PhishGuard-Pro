
from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.training_submission import router


def create_client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def valid_form_data():
    return {
        "campaign_id": 1,
        "participant_name": "Test Participant",
    }


def test_invalid_campaign_id_is_rejected():
    client = create_client()
    data = valid_form_data()
    data["campaign_id"] = 0

    response = client.post("/training/submit", data=data)

    assert response.status_code == 400


def test_empty_participant_name_is_rejected():
    client = create_client()
    data = valid_form_data()
    data["participant_name"] = "   "

    response = client.post("/training/submit", data=data)

    assert response.status_code == 400


def test_oversized_participant_name_is_rejected():
    client = create_client()
    data = valid_form_data()
    data["participant_name"] = "A" * 101

    response = client.post("/training/submit", data=data)

    assert response.status_code == 400


def test_invalid_ip_consent_value_is_rejected():
    client = create_client()
    data = valid_form_data()
    data["consent_ip"] = "true"

    response = client.post("/training/submit", data=data)

    assert response.status_code == 400


def test_invalid_device_consent_value_is_rejected():
    client = create_client()
    data = valid_form_data()
    data["consent_device"] = "no"

    response = client.post("/training/submit", data=data)

    assert response.status_code == 400


def test_invalid_activity_consent_value_is_rejected():
    client = create_client()
    data = valid_form_data()
    data["consent_activity"] = "1"

    response = client.post("/training/submit", data=data)

    assert response.status_code == 400
