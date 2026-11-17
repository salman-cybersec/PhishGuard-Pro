
import pytest

from phishguard.training_page import render_training_page


def test_training_page_renders():
    html = render_training_page("Security Campaign", 1)

    assert "Security Awareness Training" in html
    assert "Security Campaign" in html
    assert 'name="participant_name"' in html
    assert 'name="consent_ip"' in html
    assert 'name="consent_device"' in html


def test_real_password_is_not_requested():
    html = render_training_page("Security Campaign", 1)

    assert 'type="password"' not in html
    assert 'name="password"' not in html
    assert 'name="otp"' not in html
    assert "No real passwords are requested" in html


def test_campaign_name_is_escaped():
    html = render_training_page(
        "<script>alert(1)</script>",
        1,
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_invalid_campaign_id_rejected():
    with pytest.raises(ValueError):
        render_training_page("Security Campaign", 0)


def test_empty_campaign_name_rejected():
    with pytest.raises(ValueError):
        render_training_page("   ", 1)


def test_long_campaign_name_rejected():
    with pytest.raises(ValueError):
        render_training_page("A" * 101, 1)


def test_awareness_scenario_renders():
    html = render_training_page(
        "Security Campaign",
        1,
        service_id="facebook",
        scenario_id="account_security",
    )

    assert "Facebook" in html
    assert "Account Security Awareness" in html
    assert "Authorized Security Awareness Simulation" in html


def test_invalid_service_rejected():
    with pytest.raises(ValueError):
        render_training_page(
            "Security Campaign",
            1,
            service_id="invalid_service",
            scenario_id="account_security",
        )


def test_invalid_scenario_rejected():
    with pytest.raises(ValueError):
        render_training_page(
            "Security Campaign",
            1,
            service_id="facebook",
            scenario_id="invalid_scenario",
        )


def test_service_and_scenario_must_be_provided_together():
    with pytest.raises(ValueError):
        render_training_page(
            "Security Campaign",
            1,
            service_id="facebook",
        )

    with pytest.raises(ValueError):
        render_training_page(
            "Security Campaign",
            1,
            scenario_id="account_security",
        )


def test_awareness_page_does_not_request_credentials():
    html = render_training_page(
        "Security Campaign",
        1,
        service_id="facebook",
        scenario_id="account_security",
    )

    assert 'type="password"' not in html
    assert 'name="password"' not in html
    assert 'name="otp"' not in html
    assert 'name="verification_code"' not in html
