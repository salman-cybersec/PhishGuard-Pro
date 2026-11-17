
from phishguard.server import app


def test_training_submission_route_registered():
    routes = {
        route.path
        for route in app.routes
        if hasattr(route, "path")
    }

    assert "/training/submit" in routes


def test_training_page_route_registered():
    routes = {
        route.path
        for route in app.routes
        if hasattr(route, "path")
    }

    assert "/training/{campaign_id}" in routes


def test_participant_report_route_registered():
    routes = {
        route.path
        for route in app.routes
        if hasattr(route, "path")
    }

    assert "/api/campaigns/{campaign_id}/participants" in routes


def test_participant_csv_export_route_registered():
    routes = {
        route.path
        for route in app.routes
        if hasattr(route, "path")
    }

    assert (
        "/api/campaigns/{campaign_id}/participants/export"
        in routes
    )
