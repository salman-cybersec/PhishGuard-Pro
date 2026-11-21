import json

from phishguard.config import DATABASE_BACKEND
from phishguard.database import get_connection, initialize_database


def save_security_scan(
    result: dict,
    html_report_path: str | None = None,
    json_report_path: str | None = None,
) -> int:
    if not isinstance(result, dict):
        raise ValueError("Invalid security scan result.")

    score_data = result.get("security_score")
    findings = result.get("findings")

    if not isinstance(score_data, dict) or not isinstance(findings, list):
        raise ValueError("Security scan data is incomplete.")

    try:
        score = int(score_data["score"])
        grade = str(score_data["grade"]).upper()
        hostname = str(result["hostname"])
        target_url = str(result["url"])
        risk_level = str(result["risk_level"]).lower()
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Invalid security scan fields.") from error

    if not 0 <= score <= 100:
        raise ValueError("Security score must be between 0 and 100.")

    if grade not in {"A", "B", "C", "D", "F"}:
        raise ValueError("Invalid security grade.")

    if risk_level not in {"low", "medium", "high"}:
        raise ValueError("Invalid risk level.")

    if not hostname or len(hostname) > 253:
        raise ValueError("Invalid hostname.")

    if not target_url or len(target_url) > 2048:
        raise ValueError("Invalid target URL.")

    # Ensure legacy databases receive the required schema migrations.
    initialize_database()

    findings_json = json.dumps(findings, ensure_ascii=False)
    result_json = json.dumps(result, ensure_ascii=False, default=str)

    query = """
        INSERT INTO security_scans (
            target_url,
            hostname,
            security_score,
            grade,
            risk_level,
            findings_json,
            result_json,
            html_report_path,
            json_report_path
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    values = (
        target_url,
        hostname,
        score,
        grade,
        risk_level,
        findings_json,
        result_json,
        html_report_path,
        json_report_path,
    )

    with get_connection() as connection:
        if DATABASE_BACKEND == "postgresql":
            query = query.replace("?", "%s")
            cursor = connection.execute(
                query + " RETURNING id",
                values,
            )
            scan_id = cursor.fetchone()[0]
        else:
            cursor = connection.execute(query, values)
            scan_id = cursor.lastrowid

    return int(scan_id)
