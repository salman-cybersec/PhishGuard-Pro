import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import phishguard.database as database
import phishguard.link_generator as generator
from phishguard.generated_link_routes import router


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_BACKEND", "sqlite")
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "routes.db")
    monkeypatch.setenv("PHISHGUARD_ALLOWED_WEBSITE_DOMAINS", "owned.example.com")
    monkeypatch.setattr(
        generator,
        "validate_website_authorization",
        lambda url: {"authorized": True, "hostname": "owned.example.com"},
    )
    database.initialize_database()

    app = FastAPI()
    app.include_router(router)

    with TestClient(app, follow_redirects=False, headers={"Origin": "http://testserver"}) as test_client:
        yield test_client


@pytest.fixture
def generated_link(client):
    return generator.create_generated_link(
        "Route Test",
        "https://owned.example.com/landing",
    )


def test_open_generated_link_shows_consent_choices(client, generated_link):
    response = client.get(f"/r/{generated_link['tracking_id']}")

    assert response.status_code == 200
    assert "Authorized Security Assessment" in response.text
    assert 'name="consent_ip"' in response.text
    assert 'name="consent_device"' in response.text
    assert "No passwords" in response.text


def test_continue_without_consent_records_no_metadata(
    client, generated_link
):
    response = client.post(
        f"/r/{generated_link['tracking_id']}/continue"
    )

    assert response.status_code == 303
    assert response.headers["location"] == generated_link["destination_url"]

    history = generator.get_generated_link_history(
        generated_link["tracking_id"]
    )
    event = history["events"][0]

    assert event["consent_ip"] == 0
    assert event["ip_address"] is None
    assert event["consent_device"] == 0
    assert event["user_agent"] is None



def test_service_link_opens_local_workspace_after_consent(client):
    service_link = generator.create_generated_link(
        "Instagram Review",
        "https://owned.example.com/landing",
        service_slug="instagram",
    )

    response = client.post(
        f"/r/{service_link['tracking_id']}/continue"
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "Instagram Security Review Workspace" in response.text
    assert "Local Assessment Simulator" in response.text
    assert "No platform sign-in imitation" in response.text


def test_service_link_consent_page_mentions_workspace(client):
    service_link = generator.create_generated_link(
        "TikTok Review",
        "https://owned.example.com/landing",
        service_slug="tiktok",
    )

    response = client.get(f"/r/{service_link['tracking_id']}")

    assert response.status_code == 200
    assert "Continue to security review workspace" in response.text

def test_continue_with_device_consent_records_user_agent(
    client, generated_link
):
    response = client.post(
        f"/r/{generated_link['tracking_id']}/continue",
        data={"consent_device": "yes"},
        headers={
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "Chrome/120.0 Safari/537.36"
            )
        },
    )

    assert response.status_code == 303

    event = generator.get_generated_link_history(
        generated_link["tracking_id"]
    )["events"][0]

    assert event["consent_device"] == 1
    assert event["user_agent"].startswith("Mozilla/")
    assert event["os_name"] == "Windows"
    assert event["device_type"] == "desktop"


def test_continue_rejects_invalid_consent_value(client, generated_link):
    response = client.post(
        f"/r/{generated_link['tracking_id']}/continue",
        data={"consent_ip": "maybe"},
    )

    assert response.status_code == 400


def test_continue_rejects_invalid_source(client, generated_link):
    response = client.post(
        f"/r/{generated_link['tracking_id']}/continue?source=unknown"
    )

    assert response.status_code == 400


def test_paused_link_cannot_be_opened(client, generated_link):
    generator.set_generated_link_status(
        generated_link["tracking_id"], "paused"
    )

    response = client.get(f"/r/{generated_link['tracking_id']}")

    assert response.status_code == 404


def test_redirect_has_no_store_header(client, generated_link):
    response = client.post(
        f"/r/{generated_link['tracking_id']}/continue"
    )

    assert response.status_code == 303
    assert response.headers["cache-control"] == "no-store"
