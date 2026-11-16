
from fastapi.testclient import TestClient

from phishguard import server


def test_participant_report_returns_json(monkeypatch):
    monkeypatch.setattr(
        server,
        "get_participant_report",
        lambda campaign_id: {
            "campaign_id": campaign_id,
            "participants": [],
        },
    )

    monkeypatch.setitem(
        server.app.dependency_overrides,
        server.verify_api_key,
        lambda: True,
    )

    client = TestClient(server.app)

    response = client.get(
        "/api/campaigns/1/participants"
    )

    assert response.status_code == 200
    assert response.json()["campaign_id"] == 1
    assert response.json()["participants"] == []


def test_participant_export_returns_csv(monkeypatch):
    monkeypatch.setattr(
        server,
        "export_participants_csv",
        lambda campaign_id: "participant_name\nTest User\n",
    )

    monkeypatch.setitem(
        server.app.dependency_overrides,
        server.verify_api_key,
        lambda: True,
    )

    client = TestClient(server.app)

    response = client.get(
        "/api/campaigns/1/participants/export"
    )

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "attachment" in response.headers["content-disposition"]
    assert "Test User" in response.text
