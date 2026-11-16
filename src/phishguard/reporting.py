
import csv
import json

from phishguard.config import REPORT_DIR
from phishguard.database import get_connection


def _safe_csv_value(value):
    if isinstance(value, str):
        if value.startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + value
    return value


def export_campaign_report(
    campaign_id: int,
    include_user_agent: bool = False,
) -> dict:

    if (
        not isinstance(campaign_id, int)
        or isinstance(campaign_id, bool)
        or campaign_id <= 0
    ):
        raise ValueError("Campaign ID must be a positive integer.")

    if not isinstance(include_user_agent, bool):
        raise ValueError("Privacy option must be true or false.")

    with get_connection() as connection:
        campaign = connection.execute(
            """
            SELECT id, name, status, created_at
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

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    event_records = []

    for event in events:
        record = {
            "id": event["id"],
            "event_type": event["event_type"],
            "created_at": event["created_at"],
        }

        if include_user_agent:
            record["user_agent"] = event["user_agent"]

        event_records.append(record)

    report = {
        "campaign": dict(campaign),
        "events": event_records,
        "total_events": len(event_records),
    }

    json_path = REPORT_DIR / f"campaign_{campaign_id}.json"
    csv_path = REPORT_DIR / f"campaign_{campaign_id}.csv"

    try:
        with json_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        fieldnames = [
            "id",
            "event_type",
            "created_at",
        ]

        if include_user_agent:
            fieldnames.append("user_agent")

        with csv_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            for record in event_records:
                safe_record = {
                    key: _safe_csv_value(value)
                    for key, value in record.items()
                }
                writer.writerow(safe_record)

    except OSError as error:
        raise RuntimeError("Unable to generate campaign reports.") from error

    return {
        "json_report": str(json_path),
        "csv_report": str(csv_path),
        "total_events": len(event_records),
        "user_agent_included": include_user_agent,
    }
