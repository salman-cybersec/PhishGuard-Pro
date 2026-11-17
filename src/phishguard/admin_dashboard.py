
from html import escape

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from phishguard.database import get_connection
from phishguard.campaigns import create_campaign
from phishguard.campaign_controls import update_campaign_status
from phishguard.link_manager import get_tracking_link
from phishguard.participant_export import export_participants_csv
from phishguard.analytics import get_campaign_analytics
from phishguard.participant_reports import get_participant_report
from phishguard.auth import (
    ADMIN_SESSION_COOKIE,
    ADMIN_SESSION_MAX_AGE,
    verify_admin_credentials,
    create_admin_session,
    verify_admin_session,
    revoke_admin_session,
)


router = APIRouter()


def _login_page(message=""):
    safe_message = escape(message)

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PhishGuard Pro - Admin Login</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                min-height: 100vh;
                display: grid;
                place-items: center;
                background: #f4f6f9;
                font-family: Arial, sans-serif;
                color: #202938;
                padding: 20px;
            }}
            .login {{
                width: 100%;
                max-width: 400px;
                background: white;
                padding: 30px;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
            }}
            h1 {{ margin-top: 0; }}
            p {{ color: #64748b; }}
            label {{
                display: block;
                margin: 20px 0 8px;
                font-weight: bold;
            }}
            input {{
                width: 100%;
                padding: 12px;
                border: 1px solid #cbd5e1;
                border-radius: 7px;
                font-size: 16px;
            }}
            button {{
                width: 100%;
                margin-top: 20px;
                padding: 13px;
                border: 0;
                border-radius: 7px;
                background: #1e40af;
                color: white;
                font-size: 16px;
                cursor: pointer;
            }}
            .error {{
                color: #b91c1c;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <main class="login">
            <h1>PhishGuard Pro</h1>
            <p>Authorized administrator login</p>
            <p class="error">{safe_message}</p>
            <form method="post" action="/admin/login">
                <label for="password">Admin password</label>
                <input
                    id="password"
                    name="password"
                    type="password"
                    maxlength="1024"
                    autocomplete="current-password"
                    required
                >
                <button type="submit">Sign in</button>
            </form>
        </main>
    </body>
    </html>
    """


@router.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    return HTMLResponse(
        content=_login_page(),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/admin/login", response_class=HTMLResponse)
def admin_login(
    request: Request,
    password: str = Form(..., max_length=1024),
):
    try:
        valid_credentials = verify_admin_credentials(password)
    except HTTPException:
        raise

    if not valid_credentials:
        return HTMLResponse(
            content=_login_page("Invalid username or password."),
            status_code=401,
            headers={"Cache-Control": "no-store"},
        )

    token = create_admin_session()

    response = RedirectResponse(
        url="/admin/dashboard",
        status_code=303,
    )

    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=token,
        max_age=ADMIN_SESSION_MAX_AGE,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/admin",
    )

    response.headers["Cache-Control"] = "no-store"

    return response


@router.post("/admin/logout")
def admin_logout(request: Request):
    verify_admin_session(request)
    revoke_admin_session(request)

    response = RedirectResponse(
        url="/admin/login",
        status_code=303,
    )

    response.delete_cookie(
        key=ADMIN_SESSION_COOKIE,
        path="/admin",
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
    )

    response.headers["Cache-Control"] = "no-store"

    return response


@router.post(
    "/admin/campaigns",
    dependencies=[Depends(verify_admin_session)],
)
def admin_create_campaign(
    request: Request,
    name: str = Form(..., max_length=100),
):
    try:
        create_campaign(name)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return RedirectResponse(
        url="/admin/dashboard?message=Campaign%20created",
        status_code=303,
    )


@router.post(
    "/admin/campaigns/{campaign_id}/status",
    dependencies=[Depends(verify_admin_session)],
)
def admin_change_campaign_status(
    campaign_id: int,
    status: str = Form(...),
):
    try:
        update_campaign_status(campaign_id, status)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return RedirectResponse(
        url="/admin/dashboard?message=Campaign%20status%20updated",
        status_code=303,
    )


@router.get(
    "/admin/campaigns/{campaign_id}/participants.csv",
    dependencies=[Depends(verify_admin_session)],
)
def admin_export_participants(campaign_id: int):
    try:
        csv_data = export_participants_csv(campaign_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="participants_{campaign_id}.csv"'
            )
        },
    )


@router.get(
    "/admin/dashboard",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_dashboard(request: Request, message: str = ""):
    with get_connection() as connection:
        campaigns = connection.execute(
            """
            SELECT id, name, tracking_code, status, created_at
            FROM campaigns
            ORDER BY id DESC
            """
        ).fetchall()

    campaign_cards = []

    for campaign in campaigns:
        campaign_id = campaign["id"]

        try:
            analytics = get_campaign_analytics(campaign_id)
            report = get_participant_report(campaign_id)
        except ValueError:
            continue

        participants = report["participants"]
        recent_rows = []

        training_link = ""
        if campaign["status"] == "active":
            training_link = get_tracking_link(
                str(request.base_url).rstrip("/"),
                campaign["tracking_code"],
            )

        for participant in participants[:5]:
            if participant["completed"]:
                participant_status = "Completed"
            elif participant["consent_activity"]:
                participant_status = "In progress"
            else:
                participant_status = "Not tracked"

            recent_rows.append(
                f"""
                <tr>
                    <td>{escape(participant["participant_name"])}</td>
                    <td>{escape(str(participant["submitted_at"]))}</td>
                    <td>{escape(str(participant["total_events"]))}</td>
                    <td>{escape(participant_status)}</td>
                </tr>
                """
            )

        recent_table = (
            "\n".join(recent_rows)
            if recent_rows
            else '<tr><td colspan="4">No participants yet.</td></tr>'
        )

        campaign_cards.append(
            f"""
            <section class="campaign">
                <h2>{escape(campaign["name"])}</h2>
                <p class="status">
                    Status: {escape(campaign["status"])}
                </p>
                <p class="training-link">
                    Training link:
                    {f'<a href="{escape(training_link, quote=True)}">{escape(training_link)}</a>' if training_link else 'Activate this campaign to enable its training link.'}
                </p>
                <div class="campaign-actions">
                    {f'<form method="post" action="/admin/campaigns/{campaign_id}/status"><input type="hidden" name="status" value="active"><button type="submit">Activate</button></form>' if campaign["status"] == "draft" else ''}
                    {f'<form method="post" action="/admin/campaigns/{campaign_id}/status"><input type="hidden" name="status" value="paused"><button type="submit">Pause</button></form>' if campaign["status"] == "active" else ''}
                    {f'<form method="post" action="/admin/campaigns/{campaign_id}/status"><input type="hidden" name="status" value="active"><button type="submit">Resume</button></form>' if campaign["status"] == "paused" else ''}
                    {f'<form method="post" action="/admin/campaigns/{campaign_id}/status"><input type="hidden" name="status" value="completed"><button type="submit">Complete</button></form>' if campaign["status"] in ("active", "paused") else ''}
                    <a class="export-link" href="/admin/campaigns/{campaign_id}/participants.csv">Export participants CSV</a>
                </div>

                <div class="metrics">
                    <div class="metric">
                        <span>Total participants</span>
                        <strong>{analytics["total_participants"]}</strong>
                    </div>
                    <div class="metric">
                        <span>Activity consent</span>
                        <strong>{analytics["activity_consent_participants"]}</strong>
                    </div>
                    <div class="metric">
                        <span>Training views</span>
                        <strong>{analytics["training_page_views"]}</strong>
                    </div>
                    <div class="metric">
                        <span>Interactions</span>
                        <strong>{analytics["form_interactions"]}</strong>
                    </div>
                    <div class="metric">
                        <span>Completed participants</span>
                        <strong>{analytics["completed_participants"]}</strong>
                    </div>
                    <div class="metric">
                        <span>Completion rate</span>
                        <strong>{analytics["completion_rate"]}%</strong>
                    </div>
                </div>

                <p class="last-activity">
                    Last activity:
                    {escape(str(analytics["last_activity"] or "No activity"))}
                </p>

                <h3>Recent participants</h3>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Submitted</th>
                                <th>Events</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recent_table}
                        </tbody>
                    </table>
                </div>
            </section>
            """
        )

    content = (
        "\n".join(campaign_cards)
        if campaign_cards
        else "<p>No campaigns available.</p>"
    )

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PhishGuard Pro - Admin Dashboard</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                padding: 30px;
                background: #f4f6f9;
                color: #202938;
                font-family: Arial, sans-serif;
            }}
            header {{
                max-width: 1100px;
                margin: 0 auto 25px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 15px;
            }}
            h1 {{ margin-bottom: 8px; }}
            .subtitle, .status, .last-activity {{ color: #64748b; }}
            main {{ max-width: 1100px; margin: auto; }}
            .campaign {{
                background: white;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                padding: 22px;
                margin-bottom: 24px;
            }}
            .metrics {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
                gap: 12px;
                margin: 22px 0;
            }}
            .metric {{
                padding: 17px;
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 9px;
            }}
            .metric span {{
                display: block;
                color: #64748b;
                font-size: 13px;
                margin-bottom: 10px;
            }}
            .metric strong {{ font-size: 24px; }}
            .table-wrap {{ overflow-x: auto; }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 12px;
                font-size: 14px;
            }}
            th, td {{
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid #e2e8f0;
            }}
            th {{ background: #f8fafc; }}
            .training-link {{ overflow-wrap: anywhere; }}
            .campaign-actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0; align-items: center; }}
            .campaign-actions form {{ margin: 0; }}
            .campaign-actions button, .export-link {{
                display: inline-block;
                padding: 9px 13px;
                border: 0;
                border-radius: 7px;
                background: #1e40af;
                color: white;
                text-decoration: none;
                cursor: pointer;
                font-size: 14px;
            }}
            .create-campaign {{
                background: white;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 24px;
            }}
            .create-campaign label {{ display: block; margin-bottom: 8px; font-weight: bold; }}
            .create-campaign input {{
                width: 100%;
                max-width: 460px;
                padding: 11px;
                border: 1px solid #cbd5e1;
                border-radius: 7px;
                font-size: 16px;
            }}
            .create-campaign button {{
                margin-top: 12px;
                padding: 11px 16px;
                border: 0;
                border-radius: 7px;
                background: #1e40af;
                color: white;
                cursor: pointer;
            }}
            .notice {{ color: #166534; }}
            .logout button {{
                padding: 10px 16px;
                border: 0;
                border-radius: 7px;
                background: #1e40af;
                color: white;
                cursor: pointer;
            }}
            @media (max-width: 600px) {{
                body {{ padding: 15px; }}
                .campaign {{ padding: 15px; }}
                header {{ align-items: flex-start; }}
            }}
        </style>
    </head>
    <body>
        <header>
            <div>
                <h1>PhishGuard Pro</h1>
                <p class="subtitle">
                    Security Awareness Campaign Dashboard
                </p>
            </div>
            <form class="logout" method="post" action="/admin/logout">
                <button type="submit">Log out</button>
            </form>
        </header>
        <main>
            {f'<p class="notice">{escape(message)}</p>' if message else ''}
            <section class="create-campaign">
                <h2>Create campaign</h2>
                <form method="post" action="/admin/campaigns">
                    <label for="campaign-name">Campaign name</label>
                    <input id="campaign-name" name="name" type="text"
                           minlength="1" maxlength="100" required>
                    <button type="submit">Create campaign</button>
                </form>
            </section>
            {content}
        </main>
    </body>
    </html>
    """

    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "no-store"},
    )
