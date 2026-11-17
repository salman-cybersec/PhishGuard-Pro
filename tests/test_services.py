
import pytest

from phishguard.services import (
    SERVICES,
    list_services,
    get_service,
    get_service_scenarios,
    validate_scenario,
)


def test_catalogue_contains_at_least_20_services():
    assert len(SERVICES) >= 20


def test_list_services_returns_all_services():
    result = list_services()

    assert len(result) == len(SERVICES)
    assert all("id" in item for item in result)
    assert all("name" in item for item in result)
    assert all("scenarios" in item for item in result)


def test_get_facebook_service():
    result = get_service("facebook")

    assert result["id"] == "facebook"
    assert result["name"] == "Facebook"


def test_service_lookup_is_case_insensitive():
    result = get_service("TikTok")

    assert result["id"] == "tiktok"


def test_unknown_service_is_rejected():
    with pytest.raises(ValueError):
        get_service("unknown-service")


def test_invalid_service_type_is_rejected():
    with pytest.raises(ValueError):
        get_service(None)


def test_service_scenarios_have_labels():
    result = get_service_scenarios("instagram")

    assert len(result) >= 1
    assert all("id" in item for item in result)
    assert all("name" in item for item in result)


def test_valid_scenario_is_accepted():
    result = validate_scenario(
        "facebook",
        "account_security",
    )

    assert result["service_id"] == "facebook"
    assert result["scenario_id"] == "account_security"


def test_invalid_scenario_is_rejected():
    with pytest.raises(ValueError):
        validate_scenario(
            "facebook",
            "payment_security",
        )


def test_scenario_validation_is_case_insensitive():
    result = validate_scenario(
        "facebook",
        "ACCOUNT_SECURITY",
    )

    assert result["scenario_id"] == "account_security"


def test_returned_scenarios_cannot_modify_catalogue():
    result = get_service("facebook")
    result["scenarios"].clear()

    assert SERVICES["facebook"]["scenarios"]


def test_list_service_scenarios_cannot_modify_catalogue():
    result = list_services()
    result[0]["scenarios"].clear()

    assert SERVICES["facebook"]["scenarios"]
