
from phishguard.server import app


def get_route(path):
    for route in app.routes:
        if getattr(route, "path", None) == path:
            return route

    return None


def test_training_submission_route_registered():
    assert get_route("/training/submit") is not None


def test_participant_report_route_registered():
    assert get_route(
        "/api/campaigns/{campaign_id}/participants"
    ) is not None


def test_participant_csv_export_route_registered():
    assert get_route(
        "/api/campaigns/{campaign_id}/participants/export"
    ) is not None


def test_participant_report_requires_api_key():
    route = get_route(
        "/api/campaigns/{campaign_id}/participants"
    )

    assert route is not None
    assert len(route.dependant.dependencies) > 0


def test_participant_export_requires_api_key():
    route = get_route(
        "/api/campaigns/{campaign_id}/participants/export"
    )

    assert route is not None
    assert len(route.dependant.dependencies) > 0
