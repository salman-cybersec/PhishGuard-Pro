
import pytest

from phishguard.awareness_templates import (
    TEMPLATES,
    get_template,
    render_awareness_page,
)


def test_templates_cover_all_scenarios():
    for scenario_id in TEMPLATES:
        assert scenario_id


def test_facebook_account_security_template():
    result = get_template("facebook", "account_security")

    assert result["service_id"] == "facebook"
    assert result["service_name"] == "Facebook"
    assert result["scenario_id"] == "account_security"
    assert result["title"] == "Account Security Awareness"


def test_scenario_validation_is_enforced():
    with pytest.raises(ValueError):
        get_template("facebook", "payment_security")


def test_unknown_service_is_rejected():
    with pytest.raises(ValueError):
        get_template("unknown-service", "account_security")


def test_unknown_scenario_is_rejected():
    with pytest.raises(ValueError):
        get_template("facebook", "unknown-scenario")


def test_rendered_page_contains_training_disclosure():
    page = render_awareness_page("instagram", "account_security")

    assert "Authorized Security Awareness Simulation" in page
    assert "No passwords or verification codes are requested." in page


def test_rendered_page_contains_service_and_scenario():
    page = render_awareness_page("tiktok", "account_security")

    assert "TikTok awareness scenario" in page
    assert "Account Security Awareness" in page


def test_rendered_page_does_not_contain_password_fields():
    page = render_awareness_page("facebook", "account_security")

    assert 'type="password"' not in page
    assert 'name="password"' not in page
    assert "<form" not in page.lower()


def test_rendered_page_escapes_dynamic_html():
    page = render_awareness_page("facebook", "account_security")

    assert "<script>" not in page
