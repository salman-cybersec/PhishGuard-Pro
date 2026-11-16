
import csv
import io

from phishguard import participant_export


def test_csv_export_headers(monkeypatch):
    monkeypatch.setattr(
        participant_export,
        "get_participant_report",
        lambda campaign_id: {
            "participants": [],
        },
    )

    result = participant_export.export_participants_csv(1)

    reader = csv.reader(io.StringIO(result))
    headers = next(reader)

    assert "participant_name" in headers
    assert "submitted_at" in headers
    assert "consent_ip" in headers
    assert "ip_address" in headers


def test_csv_export_participant_data(monkeypatch):
    monkeypatch.setattr(
        participant_export,
        "get_participant_report",
        lambda campaign_id: {
            "participants": [{
                "participant_name": "John",
                "submitted_at": "2026-11-16 10:00:00",
                "consent_ip": False,
                "ip_address": None,
                "consent_device": False,
                "user_agent": None,
                "browser_name": None,
                "browser_version": None,
                "os_name": None,
                "device_type": None,
            }],
        },
    )

    result = participant_export.export_participants_csv(1)
    rows = list(csv.DictReader(io.StringIO(result)))

    assert rows[0]["participant_name"] == "John"
    assert rows[0]["consent_ip"] == "False"


def test_csv_formula_injection_protection(monkeypatch):
    monkeypatch.setattr(
        participant_export,
        "get_participant_report",
        lambda campaign_id: {
            "participants": [{
                "participant_name": "=1+1",
            }],
        },
    )

    result = participant_export.export_participants_csv(1)
    rows = list(csv.DictReader(io.StringIO(result)))

    assert rows[0]["participant_name"] == "'=1+1"
