
from unittest.mock import Mock

import pytest

from phishguard import cli


def test_main_menu_contains_website_import(capsys):
    cli.show_menu()

    output = capsys.readouterr().out

    assert "Website Import & Preview" in output


def test_website_import_menu_back(monkeypatch):
    monkeypatch.setattr(
        cli.Prompt,
        "ask",
        lambda *args, **kwargs: "0",
    )

    cli.website_import_menu()


def test_website_import_rejects_unauthorized_domain(monkeypatch, capsys):
    monkeypatch.setattr(
        cli.Prompt,
        "ask",
        lambda *args, **kwargs: (
            "1" if "Select an option" in args[0]
            else "https://unauthorized.example"
        ),
    )

    monkeypatch.setattr(
        cli,
        "validate_website_authorization",
        Mock(side_effect=ValueError("Domain not authorized")),
    )

    responses = iter(["1", "https://unauthorized.example", "0"])

    monkeypatch.setattr(
        cli.Prompt,
        "ask",
        lambda *args, **kwargs: next(responses),
    )

    cli.website_import_menu()

    output = capsys.readouterr().out

    assert "Domain not authorized" in output


def test_website_import_success(monkeypatch, capsys):
    responses = iter([
        "1",
        "https://example.com",
        "0",
    ])

    monkeypatch.setattr(
        cli.Prompt,
        "ask",
        lambda *args, **kwargs: next(responses),
    )

    monkeypatch.setattr(
        cli,
        "validate_website_authorization",
        lambda url: {
            "authorized": True,
            "hostname": "example.com",
            "status": "approved",
        },
    )

    monkeypatch.setattr(
        cli,
        "import_website",
        lambda url: {
            "website": url,
            "status": "import_completed",
            "preview_id": "a" * 24,
            "preview_type": "sanitized_static_html",
            "assets_found": 2,
            "assets_imported": 2,
            "assets_skipped": 0,
            "images_connected": 1,
            "stylesheets_connected": 1,
            "javascript_executed": False,
            "credentials_collected": False,
        },
    )

    cli.website_import_menu()

    output = capsys.readouterr().out

    assert "import_completed" in output
    assert "Sanitized website preview saved successfully" in output


def test_website_import_handles_import_error(monkeypatch, capsys):
    responses = iter([
        "1",
        "https://example.com",
        "0",
    ])

    monkeypatch.setattr(
        cli.Prompt,
        "ask",
        lambda *args, **kwargs: next(responses),
    )

    monkeypatch.setattr(
        cli,
        "validate_website_authorization",
        lambda url: {
            "authorized": True,
            "hostname": "example.com",
            "status": "approved",
        },
    )

    monkeypatch.setattr(
        cli,
        "import_website",
        Mock(side_effect=RuntimeError("Import failed")),
    )

    cli.website_import_menu()

    output = capsys.readouterr().out

    assert "Import failed" in output


def test_website_import_information(monkeypatch, capsys):
    responses = iter(["2", "0"])

    monkeypatch.setattr(
        cli.Prompt,
        "ask",
        lambda *args, **kwargs: next(responses),
    )

    cli.website_import_menu()

    output = capsys.readouterr().out

    assert "JavaScript is never executed" in output
    assert "credentials" in output.lower()


def test_link_generator_history_displays_events(monkeypatch, capsys):
    responses = iter(["5", "A" * 32, "0", "0"])
    monkeypatch.setattr(
        cli.Prompt, "ask", lambda *args, **kwargs: next(responses)
    )

    captured = {}

    def mock_history(tracking_id, limit=50, offset=0):
        captured.update(tracking_id=tracking_id, limit=limit, offset=offset)
        return {
            "tracking_id": tracking_id,
            "total_events": 1,
            "limit": limit,
            "offset": offset,
            "events": [{
                "created_at": "2026-11-22 10:00:00",
                "source": "direct",
                "consent_ip": 0,
                "ip_address": None,
                "country_code": None,
                "consent_device": 0,
                "browser_name": None,
                "os_name": None,
                "device_type": None,
                "user_agent": None,
            }],
        }

    monkeypatch.setattr(cli, "get_generated_link_history", mock_history)

    cli.link_generator_menu()

    output = capsys.readouterr().out
    assert "Generated Link History" in output
    assert "direct" in output
    assert "Not collected" in output
    assert captured == {
        "tracking_id": "A" * 32,
        "limit": 50,
        "offset": 0,
    }


def test_link_generator_history_handles_invalid_id(monkeypatch, capsys):
    responses = iter(["5", "invalid", "0", "0"])
    monkeypatch.setattr(
        cli.Prompt, "ask", lambda *args, **kwargs: next(responses)
    )
    monkeypatch.setattr(
        cli,
        "get_generated_link_history",
        Mock(side_effect=ValueError("Invalid tracking ID.")),
    )

    cli.link_generator_menu()

    assert "Invalid tracking ID" in capsys.readouterr().out


def test_link_generator_datewise_analytics_displays_report(monkeypatch, capsys):
    responses = iter(["6", "2026-11-20", "2026-11-22", "0", "0"])
    monkeypatch.setattr(
        cli.Prompt, "ask", lambda *args, **kwargs: next(responses)
    )

    captured = {}

    def mock_analytics(start_date, end_date):
        captured.update(start_date=start_date, end_date=end_date)
        return {
            "start_date": start_date,
            "end_date": end_date,
            "total_events": 3,
            "direct_events": 2,
            "qr_events": 1,
            "daily": [{
                "event_date": "2026-11-20",
                "total_events": 3,
                "direct_events": 2,
                "qr_events": 1,
            }],
        }

    monkeypatch.setattr(
        cli, "get_generated_link_analytics", mock_analytics
    )

    cli.link_generator_menu()

    output = capsys.readouterr().out
    assert "Date-wise Link Analytics" in output
    assert "Total events: 3" in output
    assert "Direct: 2" in output
    assert "QR: 1" in output
    assert "2026-11-20" in output
    assert captured == {
        "start_date": "2026-11-20",
        "end_date": "2026-11-22",
    }


def test_link_generator_datewise_analytics_handles_invalid_dates(
    monkeypatch, capsys
):
    responses = iter(["6", "invalid", "2026-11-22", "0", "0"])
    monkeypatch.setattr(
        cli.Prompt, "ask", lambda *args, **kwargs: next(responses)
    )
    monkeypatch.setattr(
        cli,
        "get_generated_link_analytics",
        Mock(side_effect=ValueError("Dates must use YYYY-MM-DD format.")),
    )

    cli.link_generator_menu()

    assert "Dates must use YYYY-MM-DD format" in capsys.readouterr().out
