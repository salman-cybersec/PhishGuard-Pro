
import pytest
from fastapi.testclient import TestClient

from phishguard import server


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(
        server.app.dependency_overrides,
        server.verify_api_key,
        lambda: True,
    )

    return TestClient(server.app)


def test_participant_report_returns_404(client, monkeypatch):
    def raise_error(campaign_id):
        raise ValueError("Campaign not found.")

    monkeypatch.setattr(
        server,
        "get_participant_report",
        raise_error,
    )

    response = client.get(
        "/api/campaigns/999/participants"
    )

    assert response.status_code == 404


def test_participant_export_returns_404(client, monkeypatch):
    def raise_error(campaign_id):
        raise ValueError("Campaign not found.")

    monkeypatch.setattr(
        server,
        "export_participants_csv",
        raise_error,
    )

    response = client.get(
        "/api/campaigns/999/participants/export"
    )

    assert response.status_code == 404
