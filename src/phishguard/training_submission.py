
import secrets

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from phishguard.database import get_connection


router = APIRouter()


@router.post("/training/submit", response_class=HTMLResponse)
def submit_training_form(
    request: Request,
    campaign_id: int = Form(...),
    participant_name: str = Form(...),
    consent_ip: str | None = Form(None),
    consent_device: str | None = Form(None),
):
    name = participant_name.strip()

    if campaign_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid campaign.")

    if not name or len(name) > 100:
        raise HTTPException(
            status_code=400,
            detail="Participant name must contain 1-100 characters.",
        )

    if consent_ip not in (None, "yes"):
        raise HTTPException(status_code=400, detail="Invalid IP consent.")

    if consent_device not in (None, "yes"):
        raise HTTPException(status_code=400, detail="Invalid device consent.")

    collect_ip = consent_ip == "yes"
    collect_device = consent_device == "yes"

    client_ip = None
    user_agent = None

    if collect_ip and request.client:
        client_ip = request.client.host

    if collect_device:
        user_agent = request.headers.get("user-agent", "")[:500] or None

    participant_token = secrets.token_urlsafe(32)

    try:
        with get_connection() as connection:
            campaign = connection.execute(
                """
                SELECT id FROM campaigns
                WHERE id = ? AND status = 'active'
                """,
                (campaign_id,),
            ).fetchone()

            if campaign is None:
                raise HTTPException(
                    status_code=404,
                    detail="Active campaign not found.",
                )

            connection.execute(
                """
                INSERT INTO participants (
                    campaign_id,
                    participant_token,
                    participant_name,
                    consent_ip,
                    ip_address,
                    consent_device,
                    user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    participant_token,
                    name,
                    int(collect_ip),
                    client_ip,
                    int(collect_device),
                    user_agent,
                ),
            )

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to save training submission.",
        ) from error

    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Training Complete</title>
    </head>
    <body>
        <h2>Training submission completed</h2>
        <p>This was an authorized security-awareness simulation.</p>
        <p>No password was requested or collected.</p>
    </body>
    </html>
    """
