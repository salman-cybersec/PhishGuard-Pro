
from html import escape

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from phishguard.database import get_connection
from phishguard.analytics import get_campaign_analytics
from phishguard.participant_reports import get_participant_report


router = APIRouter()


def _format_number(value):
    return escape(str(value if value is not None else 0))


@router.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard():
    with get_connection() as connection:
        campaigns = connection.execute(
            """
            SELECT id, name, status, created_at
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

        for participant in participants[:5]:
            recent_rows.append(
                f"""
                <tr>
                    <td>{escape(participant["participant_name"])}</td>
                    <td>{escape(str(participant["submitted_at"]))}</td>
                    <td>{_format_number(participant["total_events"])}</td>
                    <td>{escape(participant["completion_status"] if "completion_status" in participant else ("Completed" if participant["completed"] else "In progress" if participant["consent_activity"] else "Not tracked"))}</td>
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

                <div class="metrics">
                    <div class="metric">
                        <span>Total participants</span>
                        <strong>{_format_number(analytics["total_participants"])}</strong>
                    </div>
                    <div class="metric">
                        <span>Activity consent</span>
                        <strong>{_format_number(analytics["activity_consent_participants"])}</strong>
                    </div>
                    <div class="metric">
                        <span>Training views</span>
                        <strong>{_format_number(analytics["training_page_views"])}</strong>
                    </div>
                    <div class="metric">
                        <span>Interactions</span>
                        <strong>{_format_number(analytics["form_interactions"])}</strong>
                    </div>
                    <div class="metric">
                        <span>Completed participants</span>
                        <strong>{_format_number(analytics["completed_participants"])}</strong>
                    </div>
                    <div class="metric">
                        <span>Completion rate</span>
                        <strong>{_format_number(analytics["completion_rate"])}%</strong>
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
            * {{
                box-sizing: border-box;
            }}

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
            }}

            h1 {{
                margin-bottom: 8px;
            }}

            .subtitle {{
                color: #64748b;
            }}

            main {{
                max-width: 1100px;
                margin: auto;
            }}

            .campaign {{
                background: white;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                padding: 22px;
                margin-bottom: 24px;
            }}

            .status,
            .last-activity {{
                color: #64748b;
                font-size: 14px;
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

            .metric strong {{
                font-size: 24px;
            }}

            .table-wrap {{
                overflow-x: auto;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 12px;
                font-size: 14px;
            }}

            th,
            td {{
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid #e2e8f0;
            }}

            th {{
                background: #f8fafc;
            }}

            @media (max-width: 600px) {{
                body {{
                    padding: 15px;
                }}

                .campaign {{
                    padding: 15px;
                }}
            }}
        </style>
    </head>
    <body>
        <header>
            <h1>PhishGuard Pro</h1>
            <p class="subtitle">
                Security Awareness Campaign Dashboard
            </p>
        </header>

        <main>
            {content}
        </main>
    </body>
    </html>
    """

    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "no-store"},
    )
