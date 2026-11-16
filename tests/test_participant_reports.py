
import pytest

from phishguard import database
from phishguard.participant_reports import get_participant_report


@pytest.fixture
def test_database(tmp_path, monkeypatch):
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
            VALUES ('Awareness Test', 'REPORT123', 'active')
            """
        )

        connection.execute(
            """
            INSERT INTO participants (
                campaign_id,
                participant_token,
                participant_name,
                consent_ip,
                ip_address,
                consent_device,
                user_agent
            )
            VALUES (1, 'test-token-123456789012345', 'John',
                    1, '203.0.113.10', 1, 'Test Browser')
            """
        )

        connection.execute(
            """
            INSERT INTO participants (
                campaign_id,
                participant_token,
                participant_name
            )
            VALUES (1, 'test-token-223456789012345', 'Sarah')
            """
        )


def test_participant_report(test_database):
    report = get_participant_report(1)

    assert report["campaign_name"] == "Awareness Test"
    assert report["total_participants"] == 2
    assert report["participants"][0]["participant_name"] == "Sarah"
    assert report["participants"][1]["participant_name"] == "John"


def test_consent_data_is_reported(test_database):
    report = get_participant_report(1)

    john = next(
        item for item in report["participants"]
        if item["participant_name"] == "John"
    )

    assert john["consent_ip"] is True
    assert john["ip_address"] == "203.0.113.10"
    assert john["consent_device"] is True
    assert john["user_agent"] == "Test Browser"


def test_unconsented_data_is_hidden(test_database):
    report = get_participant_report(1)

    sarah = next(
        item for item in report["participants"]
        if item["participant_name"] == "Sarah"
    )

    assert sarah["ip_address"] is None
    assert sarah["user_agent"] is None


def test_invalid_campaign_id():
    with pytest.raises(ValueError):
        get_participant_report(0)


def test_missing_campaign():
    with pytest.raises(ValueError):
        get_participant_report(999)
