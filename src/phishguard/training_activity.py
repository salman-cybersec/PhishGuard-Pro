
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse

from phishguard.database import get_connection
from phishguard.training_submission import COOKIE_NAME


router = APIRouter()

ALLOWED_TRAINING_EVENTS = {
    "training_page_view",
    "form_interaction",
    "simulation_complete",
}


@router.post("/training/activity/{campaign_id}")
def record_training_activity(
    campaign_id: int,
    request: Request,
    event_type: str = Form(...),
):
    if campaign_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="Invalid campaign.",
        )

    if event_type not in ALLOWED_TRAINING_EVENTS:
        raise HTTPException(
            status_code=400,
            detail="Invalid training event.",
        )

    participant_token = request.cookies.get(COOKIE_NAME)

    if not participant_token:
        raise HTTPException(
            status_code=401,
            detail="Participant session not found.",
        )

    try:
        with get_connection() as connection:
            participant = connection.execute(
                """
                SELECT
                    id,
                    campaign_id,
                    consent_activity,
                    consent_device,
                    user_agent
                FROM participants
                WHERE participant_token = ?
                  AND campaign_id = ?
                """,
                (participant_token, campaign_id),
            ).fetchone()

            if participant is None:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid participant session.",
                )

            if participant["consent_activity"] != 1:
                raise HTTPException(
                    status_code=403,
                    detail="Activity tracking consent not granted.",
                )

            campaign = connection.execute(
                """
                SELECT id
                FROM campaigns
                WHERE id = ? AND status = 'active'
                """,
                (campaign_id,),
            ).fetchone()

            if campaign is None:
                raise HTTPException(
                    status_code=404,
                    detail="Active campaign not found.",
                )

            event_user_agent = (
                participant["user_agent"]
                if participant["consent_device"] == 1
                else None
            )

            cursor = connection.execute(
                """
                INSERT INTO events (
                    campaign_id,
                    participant_id,
                    event_type,
                    user_agent
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    participant["id"],
                    event_type,
                    event_user_agent,
                ),
            )

            event_id = cursor.lastrowid

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to record training activity.",
        ) from error

    return JSONResponse(
        status_code=201,
        content={
            "status": "recorded",
            "event_id": event_id,
            "event_type": event_type,
        },
        headers={"Cache-Control": "no-store"},
    )
