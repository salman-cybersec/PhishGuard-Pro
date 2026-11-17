
import ipaddress
import secrets

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from phishguard.database import get_connection
from phishguard.device_info import parse_device_info


router = APIRouter()

COOKIE_NAME = "phishguard_participant"
COOKIE_MAX_AGE = 8 * 60 * 60


@router.post("/training/submit", response_class=HTMLResponse)
def submit_training_form(
    request: Request,
    campaign_id: int = Form(...),
    participant_name: str = Form(...),
    consent_ip: str | None = Form(None),
    consent_device: str | None = Form(None),
    consent_activity: str | None = Form(None),
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

    if consent_activity not in (None, "yes"):
        raise HTTPException(status_code=400, detail="Invalid activity consent.")

    collect_ip = consent_ip == "yes"
    collect_device = consent_device == "yes"
    collect_activity = consent_activity == "yes"

    client_ip = None
    user_agent = None
    device_info = {}

    if collect_ip and request.client:
        try:
            client_ip = str(
                ipaddress.ip_address(request.client.host)
            )
        except ValueError:
            client_ip = None

    if collect_device:
        user_agent = request.headers.get("user-agent", "")[:500] or None

        if user_agent:
            device_info = parse_device_info(user_agent)

    participant_token = secrets.token_urlsafe(32)

    try:
        with get_connection() as connection:
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

            cursor = connection.execute(
                """
                INSERT INTO participants (
                    campaign_id,
                    participant_token,
                    participant_name,
                    consent_ip,
                    ip_address,
                    consent_device,
                    user_agent,
                    browser_name,
                    browser_version,
                    os_name,
                    device_type,
                    consent_activity
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    participant_token,
                    name,
                    int(collect_ip),
                    client_ip,
                    int(collect_device),
                    user_agent,
                    device_info.get("browser_name"),
                    device_info.get("browser_version"),
                    device_info.get("os_name"),
                    device_info.get("device_type"),
                    int(collect_activity),
                ),
            )

            participant_id = cursor.lastrowid

            if collect_activity:
                connection.execute(
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
                        participant_id,
                        "form_interaction",
                        user_agent if collect_device else None,
                    ),
                )

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to save training submission.",
        ) from error

    activity_section = ""

    if collect_activity:
        activity_section = f"""
        <p>Your consented training activity can now be recorded.</p>

        <button id="complete-training" type="button">
            Complete training
        </button>

        <p id="activity-status" role="status"></p>

        <script>
        (() => {{
            const endpoint = "/training/activity/{campaign_id}";
            const status = document.getElementById("activity-status");
            const button = document.getElementById("complete-training");

            async function sendEvent(eventType) {{
                const body = new URLSearchParams();
                body.set("event_type", eventType);

                const response = await fetch(endpoint, {{
                    method: "POST",
                    credentials: "same-origin",
                    headers: {{
                        "Content-Type": "application/x-www-form-urlencoded"
                    }},
                    body: body.toString()
                }});

                if (!response.ok) {{
                    throw new Error("Activity event could not be saved.");
                }}

                return response.json();
            }}

            sendEvent("training_page_view").catch(() => {{
                status.textContent = "Training view event could not be recorded.";
            }});

            button.addEventListener("click", async () => {{
                button.disabled = true;

                try {{
                    await sendEvent("simulation_complete");
                    status.textContent = "Training completion recorded.";
                }} catch (error) {{
                    status.textContent = "Unable to record completion. Please contact your supervisor.";
                    button.disabled = false;
                }}
            }});
        }})();
        </script>
        """

    response = HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Training Complete</title>
        </head>
        <body>
            <h2>Training submission completed</h2>
            <p>This was an authorized security-awareness simulation.</p>
            <p>No password or verification code was requested or collected.</p>
            <p>Your selected consent preferences have been applied.</p>
            {activity_section}
        </body>
        </html>
        """
    )

    response.headers["Cache-Control"] = "no-store"

    if collect_activity:
        response.set_cookie(
            key=COOKIE_NAME,
            value=participant_token,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="lax",
            path="/training",
        )

    return response
