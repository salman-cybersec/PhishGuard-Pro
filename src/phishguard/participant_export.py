
import csv
import io
import json

from phishguard.participant_reports import get_participant_report


def _safe_csv_value(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)

    if isinstance(value, str):
        # Prevent spreadsheet formula injection.
        if value.lstrip().startswith(("=", "+", "-", "@")):
            value = "'" + value

    return value


def export_participants_csv(campaign_id: int) -> str:
    report = get_participant_report(campaign_id)

    output = io.StringIO(newline="")

    fields = [
        "participant_name",
        "submitted_at",
        "consent_ip",
        "ip_address",
        "consent_device",
        "user_agent",
        "browser_name",
        "browser_version",
        "os_name",
        "device_type",
        "consent_activity",
        "total_events",
        "interaction_count",
        "completion_count",
        "completed",
        "last_activity",
        "events",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fields,
        extrasaction="ignore",
    )

    writer.writeheader()

    for participant in report["participants"]:
        row = {}

        for field in fields:
            value = participant.get(field)

            # Keep event history readable in a single CSV cell.
            if field == "events":
                value = json.dumps(
                    value or [],
                    ensure_ascii=False,
                )

            row[field] = _safe_csv_value(value)

        writer.writerow(row)

    return output.getvalue()
