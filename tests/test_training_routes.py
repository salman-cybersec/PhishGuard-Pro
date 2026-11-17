
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.training_submission import router as submission_router
from phishguard.training_routes import router as training_page_router


app = FastAPI()
app.include_router(submission_router)
app.include_router(training_page_router)

client = TestClient(app)


def test_training_router_has_submit_endpoint():
    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "Test Participant",
        },
    )

    assert response.status_code in (200, 404)


@patch("phishguard.training_routes.get_connection")
def test_active_campaign_training_page(mock_connection):
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = {
        "id": 1,
        "name": "Security Awareness Test",
    }
    mock_connection.return_value.__enter__.return_value = connection

    response = client.get(
        "/training/1",
        params={
            "service_id": "facebook",
            "scenario_id": "account_security",
        },
    )

    assert response.status_code == 200
    assert "Security Awareness Training" in response.text
    assert "Facebook" in response.text
    assert "Account Security Awareness" in response.text


@patch("phishguard.training_routes.get_connection")
def test_missing_campaign_returns_404(mock_connection):
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = None
    mock_connection.return_value.__enter__.return_value = connection

    response = client.get("/training/999")

    assert response.status_code == 404


@patch("phishguard.training_routes.get_connection")
def test_invalid_scenario_returns_400(mock_connection):
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = {
        "id": 1,
        "name": "Security Awareness Test",
    }
    mock_connection.return_value.__enter__.return_value = connection

    response = client.get(
        "/training/1",
        params={
            "service_id": "facebook",
            "scenario_id": "invalid_scenario",
        },
    )

    assert response.status_code == 400


def test_invalid_campaign_id_is_rejected():
    response = client.get("/training/0")

    assert response.status_code == 400


@patch("phishguard.training_routes.get_connection")
def test_training_page_has_no_password_field(mock_connection):
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = {
        "id": 1,
        "name": "Security Awareness Test",
    }
    mock_connection.return_value.__enter__.return_value = connection

    response = client.get("/training/1")

    assert response.status_code == 200
    assert 'type="password"' not in response.text
    assert 'name="password"' not in response.text
