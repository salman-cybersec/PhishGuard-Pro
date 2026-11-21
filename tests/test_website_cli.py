
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
