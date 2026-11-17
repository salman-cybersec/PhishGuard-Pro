
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse

from phishguard.database import get_connection
from phishguard.training_submission import COOKIE_NAME
from phishguard.monitor import log_training_event


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
                    participant_name,
                    consent_activity,
                    consent_ip,
                    ip_address,
                    consent_device,
                    user_agent,
                    browser_name,
                    os_name,
                    device_type
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

            log_training_event(
                event_type=event_type,
                campaign_id=campaign_id,
                participant_name=participant["participant_name"],
                ip_address=(
                    participant["ip_address"]
                    if participant["consent_ip"] == 1
                    else None
                ),
                browser_name=(
                    participant["browser_name"]
                    if participant["consent_device"] == 1
                    else None
                ),
                os_name=(
                    participant["os_name"]
                    if participant["consent_device"] == 1
                    else None
                ),
                device_type=(
                    participant["device_type"]
                    if participant["consent_device"] == 1
                    else None
                ),
            )

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
