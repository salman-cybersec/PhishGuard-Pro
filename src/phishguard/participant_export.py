
import csv
import io

from phishguard.participant_reports import get_participant_report


def export_participants_csv(campaign_id: int) -> str:
    report = get_participant_report(campaign_id)

    output = io.StringIO()

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
    ]

    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()

    for participant in report["participants"]:
        row = {}

        for field in fields:
            value = participant.get(field)

            if isinstance(value, str):
                # Prevent spreadsheet formula injection.
                if value.lstrip().startswith(("=", "+", "-", "@")):
                    value = "'" + value

            row[field] = value

        writer.writerow(row)

    return output.getvalue()
