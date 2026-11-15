import csv
import json

from pathlib import Path

from phishguard.database import get_connection
from phishguard.config import REPORT_DIR


def export_campaign_report(campaign_id: int) -> dict:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        campaign = connection.execute(
            """
            SELECT id, name, tracking_code, status, created_at
            FROM campaigns
            WHERE id = ?
            """,
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

        events = connection.execute(
            """
            SELECT id, event_type, created_at, user_agent
            FROM events
            WHERE campaign_id = ?
            ORDER BY id DESC
            """,
            (campaign_id,),
        ).fetchall()

    report = {
        "campaign": dict(campaign),
        "events": [dict(event) for event in events],
        "total_events": len(events),
    }

    json_path = REPORT_DIR / f"campaign_{campaign_id}.json"
    csv_path = REPORT_DIR / f"campaign_{campaign_id}.csv"

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "id",
                "event_type",
                "created_at",
                "user_agent",
            ],
        )

        writer.writeheader()
        writer.writerows(report["events"])

    return {
        "json_report": str(json_path),
        "csv_report": str(csv_path),
        "total_events": len(events),
    }
