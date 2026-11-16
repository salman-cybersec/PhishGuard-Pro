
from phishguard.server import app


def test_training_submission_route_registered():
    routes = {
        route.path
        for route in app.routes
        if hasattr(route, "path")
    }

    assert "/training/submit" in routes
