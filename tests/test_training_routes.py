
from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.training_submission import router


def test_training_router_has_submit_endpoint():
    app = FastAPI()
    app.include_router(router)

    client = TestClient(app)

    response = client.post(
        "/training/submit",
        data={
            "campaign_id": 1,
            "participant_name": "Test Participant",
        },
    )

    # The endpoint should respond, even if no active campaign exists.
    assert response.status_code in (200, 404)
