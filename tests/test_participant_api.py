
from phishguard.server import app
from phishguard.auth import verify_api_key


def find_route(path):
    for route in app.routes:
        if getattr(route, "path", None) == path:
            return route

    return None


def test_participant_report_has_api_key_protection():
    route = find_route(
        "/api/campaigns/{campaign_id}/participants"
    )

    assert route is not None

    dependencies = [
        dependency.call
        for dependency in route.dependant.dependencies
    ]

    assert verify_api_key in dependencies


def test_participant_export_has_api_key_protection():
    route = find_route(
        "/api/campaigns/{campaign_id}/participants/export"
    )

    assert route is not None

    dependencies = [
        dependency.call
        for dependency in route.dependant.dependencies
    ]

    assert verify_api_key in dependencies
