import html
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from phishguard.config import REPORT_DIR
from phishguard.security_score import calculate_security_score


def _safe(value):
    return html.escape(str(value if value is not None else "N/A"))


def _get_security_score(result, findings):
    score = result.get("security_score")

    if not isinstance(score, dict):
        score = calculate_security_score(findings)

    return score


def export_security_html_report(result: dict) -> dict:
    if not isinstance(result, dict):
        raise ValueError("Invalid security analysis result.")

    findings = result.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("Invalid findings data.")

    security_score = _get_security_score(result, findings)

    headers = result.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}

    tls = result.get("tls", {})
    if not isinstance(tls, dict):
        tls = {}

    present = headers.get("present", [])
    missing = headers.get("missing", [])

    if not isinstance(present, list) or not isinstance(missing, list):
        raise ValueError("Invalid security header data.")

    finding_rows = ""

    for item in findings:
        if not isinstance(item, dict):
            continue

        finding_rows += f"""
        <tr>
            <td>{_safe(item.get("severity", "unknown"))}</td>
            <td>{_safe(item.get("finding", "Unknown finding"))}</td>
            <td>{_safe(item.get("remediation", "No recommendation available"))}</td>
        </tr>
        """

    if not finding_rows:
        finding_rows = '<tr><td colspan="3">No findings recorded.</td></tr>'

    ip_list = result.get("resolved_ips", [])
    if not isinstance(ip_list, list):
        ip_list = []

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    filename = (
        f"security_scan_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_"
        f"{uuid4().hex[:8]}.html"
    )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard Pro - Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 35px auto; padding: 0 20px;
       max-width: 1050px; color: #202938; background: #f5f7fa; }}
header, section {{ background: white; padding: 22px; margin-bottom: 18px;
                   border-radius: 9px; }}
h1, h2 {{ color: #17365d; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th, td {{ padding: 11px; border: 1px solid #dce2e9; text-align: left;
          overflow-wrap: anywhere; }}
th {{ background: #edf2f7; }}
.risk {{ font-weight: bold; }}
footer {{ color: #687386; font-size: 13px; margin: 20px 0; }}
</style>
</head>
<body>
<header>
<h1>PhishGuard Pro</h1>
<h2>Website Security Analysis Report</h2>
<p><strong>Target:</strong> {_safe(result.get("hostname"))}</p>
<p><strong>URL:</strong> {_safe(result.get("url"))}</p>
<p><strong>Generated:</strong> {_safe(generated)}</p>
<p class="risk"><strong>Risk Level:</strong> {_safe(result.get("risk_level", "unknown")).upper()}</p>
</header>

<section>
<h2>Scan Overview</h2>
<table>
<tr><th>Metric</th><th>Result</th></tr>
<tr><td>HTTP Status</td><td>{_safe(result.get("http_status"))}</td></tr>
<tr><td>Resolved IP Addresses</td><td>{_safe(", ".join(str(ip) for ip in ip_list))}</td></tr>
<tr><td>TLS Version</td><td>{_safe(tls.get("version"))}</td></tr>
<tr><td>Certificate Expiry</td><td>{_safe(tls.get("expires_at"))}</td></tr>
<tr><td>Days Remaining</td><td>{_safe(tls.get("days_remaining"))}</td></tr>
<tr><td>Total Findings</td><td>{len(findings)}</td></tr>
<tr><td>Security Score</td><td>{_safe(security_score.get("score"))}/100</td></tr>
<tr><td>Grade</td><td>{_safe(security_score.get("grade"))}</td></tr>
<tr><td>Critical Findings</td><td>{_safe(security_score.get("breakdown", {}).get("critical", 0))}</td></tr>
<tr><td>High Findings</td><td>{_safe(security_score.get("breakdown", {}).get("high", 0))}</td></tr>
<tr><td>Medium Findings</td><td>{_safe(security_score.get("breakdown", {}).get("medium", 0))}</td></tr>
<tr><td>Low Findings</td><td>{_safe(security_score.get("breakdown", {}).get("low", 0))}</td></tr>
</table>
</section>

<section>
<h2>Security Headers</h2>
<h3>Present</h3>
<p>{_safe(", ".join(str(x) for x in present) or "None")}</p>
<h3>Missing</h3>
<p>{_safe(", ".join(str(x) for x in missing) or "None")}</p>
</section>

<section>
<h2>Findings and Recommended Fixes</h2>
<table>
<tr><th>Severity</th><th>Finding</th><th>Recommended Fix</th></tr>
{finding_rows}
</table>
</section>

<footer>
This report contains results from the PhishGuard Pro HTTPS, TLS and
security-header checks. It is not a guarantee that the website is secure.
Only authorized testing is permitted.
</footer>
</body>
</html>
"""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / filename

    try:
        with report_path.open("x", encoding="utf-8") as file:
            file.write(document)
    except OSError as error:
        raise RuntimeError("Unable to generate security HTML report.") from error

    return {
        "html_report": str(report_path),
        "hostname": result.get("hostname", "unknown"),
        "total_findings": len(findings),
    }
def export_security_json_report(result: dict) -> dict:
    import json

    if not isinstance(result, dict):
        raise ValueError("Invalid security scan result.")

    findings = result.get("findings", [])
    headers = result.get("headers", {})
    tls = result.get("tls", {})

    if not isinstance(findings, list):
        raise ValueError("Invalid findings data.")
    if not isinstance(headers, dict) or not isinstance(tls, dict):
        raise ValueError("Invalid security scan metadata.")

    security_score = _get_security_score(result, findings)

    report_data = dict(result)
    report_data["security_score"] = security_score
    report_data["report_type"] = "PhishGuard Pro Security Scan"
    report_data["generated_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"security_scan_{timestamp}_{uuid4().hex[:8]}.json"

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / filename

    try:
        with report_path.open("x", encoding="utf-8") as file:
            json.dump(
                report_data,
                file,
                indent=2,
                ensure_ascii=False,
            )
            file.write("\n")
    except (OSError, TypeError, ValueError) as error:
        raise RuntimeError("Unable to generate security JSON report.") from error

    return {
        "json_report": str(report_path),
        "hostname": result.get("hostname", "unknown"),
        "total_findings": len(findings),
    }
