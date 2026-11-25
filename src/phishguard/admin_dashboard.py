
from html import escape
from phishguard.service_workspaces import SERVICE_WORKSPACES, render_service_workspace
import json
import datetime as dt

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse as _HTMLResponse, RedirectResponse, Response, FileResponse

from phishguard.database import get_connection
from phishguard.campaigns import create_campaign
from phishguard.campaign_controls import update_campaign_status
from phishguard.link_manager import get_tracking_link
from phishguard.link_generator import create_generated_link, create_generated_links, resolve_generated_link, set_generated_link_status, get_generated_link_history, get_generated_link_analytics
from phishguard.qr_generator import generate_qr_code
from phishguard.config import LOCAL_PREVIEW_BASE_URL, build_preview_url
from phishguard.website_manager import import_website
from phishguard.website_authorization import validate_website_authorization
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
    verify_admin_origin,
)

from phishguard.login_throttle import (
    check_login_allowed,
    record_login_failure,
    clear_login_failures,
)


from phishguard.security_analyzer import analyze_website, validate_target_url
from phishguard.security_scan_store import save_security_scan
from phishguard.full_scan import analyze_full_website
from phishguard.domain_intelligence import analyze_domain_intelligence
from phishguard.dns_security import analyze_dns_security
from phishguard.network_intelligence import analyze_network_addresses
from phishguard.subdomain_discovery import discover_subdomains

router = APIRouter()

# Shared Modern Enterprise UI for standalone admin pages.
ADMIN_UI_CSS = """
:root {
  color-scheme: light;
  --pg-bg: #f4f7fc;
  --pg-surface: #ffffff;
  --pg-ink: #17233d;
  --pg-muted: #71809a;
  --pg-line: #e5ebf4;
  --pg-blue: #315efb;
  --pg-blue-dark: #244bd0;
  --pg-shadow: 0 8px 28px rgba(24, 45, 85, .06);
}
* { box-sizing: border-box; }
html { min-width: 320px; }
body {
  background: var(--pg-bg) !important;
  color: var(--pg-ink) !important;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system,
               BlinkMacSystemFont, "Segoe UI", sans-serif !important;
  line-height: 1.55;
}
main { max-width: 1180px; }
h1, h2, h3 { color: var(--pg-ink); letter-spacing: -.025em; }
h1 { font-size: clamp(25px, 3vw, 32px) !important; font-weight: 750; }
h2 { font-weight: 700; }
p { line-height: 1.65; }
a { color: var(--pg-blue); }
input:not([type=checkbox]):not([type=radio]),
select, textarea {
  max-width: 100%;
  border: 1px solid #d6dfec !important;
  border-radius: 9px !important;
  background: #fff;
  color: var(--pg-ink);
  font: inherit;
  transition: border-color .15s, box-shadow .15s;
}
input:not([type=checkbox]):not([type=radio]):focus,
select:focus, textarea:focus {
  outline: none;
  border-color: var(--pg-blue) !important;
  box-shadow: 0 0 0 3px rgba(49, 94, 251, .12);
}
button, input[type=submit] {
  border: 0;
  border-radius: 9px;
  background: var(--pg-blue);
  color: white;
  font: inherit;
  font-weight: 650;
  cursor: pointer;
  transition: background .15s, transform .15s;
}
button:hover, input[type=submit]:hover {
  background: var(--pg-blue-dark);
}
button:focus-visible, a:focus-visible {
  outline: 3px solid rgba(49, 94, 251, .35);
  outline-offset: 3px;
}
table { border-collapse: collapse; }
th {
  background: #f5f8fd !important;
  color: #53627a;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .045em;
}
th, td { border-bottom: 1px solid var(--pg-line); }
tr:hover td { background: #f9fbff; }
.panel, .card, .tool, .service-card, main > section {
  border-color: var(--pg-line);
}
.pg-topbar {
  position: sticky;
  top: 0;
  z-index: 50;
  display: flex;
  align-items: center;
  gap: 22px;
  min-height: 68px;
  padding: 12px clamp(16px, 4vw, 42px);
  background: rgba(255,255,255,.96);
  border-bottom: 1px solid var(--pg-line);
  box-shadow: 0 3px 14px rgba(24,45,85,.035);
  backdrop-filter: blur(12px);
}
.pg-brand {
  color: #17233d;
  font-size: 17px;
  font-weight: 800;
  text-decoration: none;
  white-space: nowrap;
}
.pg-nav {
  display: flex;
  align-items: center;
  gap: 5px;
  min-width: 0;
  overflow-x: auto;
  scrollbar-width: thin;
}
.pg-nav a {
  padding: 8px 10px;
  border-radius: 8px;
  color: #596982;
  font-size: 13px;
  font-weight: 650;
  text-decoration: none;
  white-space: nowrap;
}
.pg-nav a:hover {
  background: #edf3ff;
  color: var(--pg-blue);
}
@media (max-width: 720px) {
  .pg-topbar { align-items: flex-start; flex-direction: column; gap: 8px; padding: 12px 16px; }
  .pg-nav { width: 100%; padding-bottom: 3px; }
  body { padding-left: 14px !important; padding-right: 14px !important; }
  main { width: 100%; }
  table { min-width: 620px; }
}
"""

class HTMLResponse(_HTMLResponse):
    """Apply shared admin styling without changing route or form behavior."""

    def __init__(
        self, content="", status_code=200, headers=None,
        media_type=None, background=None
    ):
        if isinstance(content, bytes):
            html = content.decode("utf-8", errors="replace")
        else:
            html = content if isinstance(content, str) else None

        if html and "</head>" in html.lower():
            # Dashboard already owns its complete sidebar and design system.
            is_dashboard_shell = 'class="sidebar"' in html or "class='sidebar'" in html
            if not is_dashboard_shell:
                head_end = html.lower().find("</head>")
                html = (
                    html[:head_end]
                    + "<style>" + ADMIN_UI_CSS + "</style>"
                    + html[head_end:]
                )

                # Keep the login screen focused and free of authenticated navigation.
                is_login = 'class="login"' in html or "class='login'" in html
                if not is_login and "<body" in html.lower():
                    body_open = html.lower().find(">", html.lower().find("<body"))
                    nav = (
                        '<header class="pg-topbar">'
                        '<a class="pg-brand" href="/admin/dashboard">PhishGuard Pro</a>'
                        '<nav class="pg-nav" aria-label="Admin navigation">'
                        '<a href="/admin/dashboard">Dashboard</a>'
                        '<a href="/admin/new-scan">New Scan</a>'
                        '<a href="/admin/full-scan">Full Scan</a>'
                        '<a href="/admin/scan-reports">Scan Reports</a>'
                        '<a href="/admin/security-tools">Security Tools</a>'
                        '<a href="/admin/phishing-links">Phishing Links</a>'
                        '<a href="/admin/link-generator">Link Generator</a>'
                        '<a href="/admin/email-validator">Email Validator</a>'
                        '<a href="/admin/web-importer">Web Importer</a>'
                        '</nav></header>'
                    )
                    html = html[:body_open + 1] + nav + html[body_open + 1:]

        if html is not None:
            content = html

        super().__init__(
            content=content,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background,
        )







def _render_structured_data(value, depth=0):
    """Render nested scan data as escaped, readable HTML tables."""
    if depth >= 8:
        return '<span class="muted">Maximum display nesting reached</span>'

    if isinstance(value, dict):
        if not value:
            return '<span class="muted">No data available</span>'

        rows = []
        for key, item in value.items():
            label = escape(str(key).replace("_", " ").title())

            if isinstance(item, (dict, list)):
                rendered = (
                    '<div class="nested-result">'
                    f'<strong>{label}</strong>'
                    f'{_render_structured_data(item, depth + 1)}'
                    '</div>'
                )
            else:
                rendered = escape(str(item)) if item is not None else "Not available"

            rows.append(f'<tr><th>{label}</th><td>{rendered}</td></tr>')

        return '<div class="table-wrap"><table class="result-data"><tbody>' + ''.join(rows) + '</tbody></table></div>'

    if isinstance(value, list):
        if not value:
            return '<span class="muted">No records available</span>'

        if all(isinstance(item, dict) for item in value):
            keys = list(dict.fromkeys(key for item in value for key in item))
            headers = ''.join(
                f'<th>{escape(str(key).replace("_", " ").title())}</th>'
                for key in keys
            )
            rows = []

            for item in value:
                cells = []
                for key in keys:
                    cell = item.get(key, "")
                    if isinstance(cell, (dict, list)):
                        rendered = _render_structured_data(cell, depth + 1)
                    else:
                        rendered = escape(str(cell)) if cell is not None else "Not available"
                    cells.append(f'<td>{rendered}</td>')
                rows.append('<tr>' + ''.join(cells) + '</tr>')

            return (
                '<div class="table-wrap"><table class="result-data">'
                f'<thead><tr>{headers}</tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table></div>'
            )

        rows = ''.join(
            '<tr><td>' + (
                _render_structured_data(item, depth + 1)
                if isinstance(item, (dict, list))
                else escape(str(item)) if item is not None else "Not available"
            ) + '</td></tr>'
            for item in value
        )
        return '<div class="table-wrap"><table class="result-data"><tbody>' + rows + '</tbody></table></div>'

    return escape(str(value)) if value is not None else "Not available"

def _render_dns_security(result):
    sections = []

    for key in ("spf", "dmarc", "caa", "mx", "dkim"):
        item = result.get(key, {})
        status = item.get("status", "unavailable").replace("_", " ").title()
        records = item.get("records", [])

        rows = []
        if records:
            for record in records:
                rows.append(
                    f"<tr><td>{escape(str(record))}</td></tr>"
                )
        else:
            rows.append(
                '<tr><td class="muted">No record data available</td></tr>'
            )

        sections.append(
            f"<section><h2>{key.upper()}</h2>"
            f'<p class="status">Status: {escape(status)}</p>'
            "<table><tbody>" + "".join(rows) + "</tbody></table></section>"
        )

    findings = result.get("findings", [])
    finding_rows = []

    for item in findings:
        severity = escape(str(item.get("severity", "info")).upper())
        finding = escape(str(item.get("finding", "")))
        evidence = escape(str(item.get("evidence", "")))
        remediation = escape(str(item.get("remediation", "")))

        finding_rows.append(
            f"<tr><td>{severity}</td><td>{finding}</td>"
            f"<td>{evidence}</td><td>{remediation}</td></tr>"
        )

    if not finding_rows:
        finding_rows.append(
            '<tr><td colspan="4">No security findings identified by these checks.</td></tr>'
        )

    summary = result.get("summary", {})

    summary_html = (
        f'<div class="summary">'
        f'<div><strong>{summary.get("total_findings", 0)}</strong><span>Total findings</span></div>'
        f'<div><strong>{summary.get("high", 0)}</strong><span>High</span></div>'
        f'<div><strong>{summary.get("medium", 0)}</strong><span>Medium</span></div>'
        f'<div><strong>{summary.get("low", 0)}</strong><span>Low</span></div>'
        f'</div>'
    )

    findings_html = (
        "<section><h2>Security Findings</h2>"
        "<table><thead><tr><th>Severity</th><th>Finding</th>"
        "<th>Evidence</th><th>Remediation</th></tr></thead>"
        "<tbody>" + "".join(finding_rows) + "</tbody></table></section>"
    )

    return summary_html + "".join(sections) + findings_html


def _render_domain_intelligence(result):
    def table(title, records):
        rows = []
        for item in records:
            if isinstance(item, dict):
                value = " | ".join(
                    f"{escape(str(key))}: {escape(str(val))}"
                    for key, val in item.items()
                )
            else:
                value = escape(str(item))
            rows.append(f"<tr><td>{value}</td></tr>")

        if not rows:
            rows.append('<tr><td class="muted">No records disclosed</td></tr>')

        return (
            f"<section><h2>{escape(title)}</h2>"
            "<table><tbody>" + "".join(rows) + "</tbody></table></section>"
        )

    sections = []
    dns = result.get("dns", {})

    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        item = dns.get(record_type, {})
        status = item.get("status", "unavailable")
        sections.append(
            table(
                f"{record_type} Records — {status.replace('_', ' ').title()}",
                item.get("records", []),
            )
        )

    email = result.get("email_security", {})
    for key in ("spf", "dmarc"):
        item = email.get(key, {})
        sections.append(
            table(
                f"{key.upper()} — {item.get('status', 'unavailable').replace('_', ' ').title()}",
                item.get("records", []),
            )
        )

    registration = result.get("registration", {})
    registration_rows = [
        {"Field": "Lookup status", "Value": registration.get("status", "unavailable")},
        {"Field": "Registrar", "Value": registration.get("registrar") or "Not disclosed"},
        {"Field": "Registration date", "Value": registration.get("registration_date") or "Not disclosed"},
        {"Field": "Expiration date", "Value": registration.get("expiration_date") or "Not disclosed"},
        {"Field": "Last changed", "Value": registration.get("last_changed") or "Not disclosed"},
    ]
    sections.append(table("Domain Registration (RDAP)", registration_rows))

    sections.append(table("IP Addresses", result.get("ip_addresses", [])))
    sections.append(table("Hosting / DNS Provider Indicators", result.get("hosting_indicators", [])))

    return "".join(sections)

def _render_network_intelligence(results):
    sections = []

    for item in results:
        rows = [
            ("IP Address", item.get("address", "Unknown")),
            ("IP Version", item.get("version", "Unknown")),
            ("Public Address", "Yes" if item.get("is_global") else "No"),
            ("Private Address", "Yes" if item.get("is_private") else "No"),
        ]

        asn_data = item.get("asn", {})
        for record in asn_data.get("records", []):
            rows.extend([
                ("ASN", record.get("asn", "Not available")),
                ("Network Prefix", record.get("network", "Not available")),
                ("Country", record.get("country", "Not available")),
                ("Registry", record.get("registry", "Not available")),
                ("Allocation Date", record.get("allocation_date", "Not available")),
                ("Network Organization", record.get("organization", "Not disclosed")),
            ])

        ptr_data = item.get("reverse_dns", {})
        ptr_records = ptr_data.get("records", [])
        rows.append(("Reverse DNS (PTR)", ", ".join(ptr_records) if ptr_records else ptr_data.get("status", "Unavailable")))

        table_rows = "".join(
            f"<tr><th>{escape(str(label))}</th><td>{escape(str(value))}</td></tr>"
            for label, value in rows
        )

        sections.append(
            f"<section><h2>{escape(str(item.get('address', 'IP Address')))}</h2>"
            f"<table>{table_rows}</table></section>"
        )

    if not sections:
        return "<p>No public IP addresses were resolved for this hostname.</p>"

    return "".join(sections)


def _render_subdomain_discovery(result):
    rows = []

    for item in result.get("subdomains", []):
        dns = item.get("dns", {})
        addresses = dns.get("A", []) + dns.get("AAAA", [])
        address_text = ", ".join(addresses) if addresses else "No public DNS address found"
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('hostname', '')))}</td>"
            f"<td>{escape(address_text)}</td>"
            f"<td>{escape(str(dns.get('status', 'unknown')))}</td>"
            f"<td>{escape(', '.join(item.get('sources', [])))}</td>"
            "</tr>"
        )

    if not rows:
        return "<p>No subdomains were returned by the discovery source.</p>"

    return (
        "<table><thead><tr><th>Subdomain</th><th>Public IP Addresses</th>"
        "<th>DNS Status</th><th>Evidence Source</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_technology_section(result):
    if not isinstance(result, dict):
        return (
            '<section class="technology-section">'
            '<h2>Technology Intelligence</h2>'
            '<p>Technology details are unavailable for this older scan.</p>'
            '</section>'
        )

    data = result.get("technologies", {})
    if not isinstance(data, dict):
        data = {}

    technologies = data.get("technologies", [])
    if not isinstance(technologies, list):
        technologies = []

    cards = []
    for item in technologies:
        if not isinstance(item, dict):
            continue

        name = escape(str(item.get("name") or "Unknown"))
        category = escape(str(item.get("category") or "Uncategorized"))
        version = escape(str(item.get("version") or "Not exposed"))
        confidence = str(item.get("confidence") or "Unconfirmed")
        evidence = item.get("evidence", [])

        if isinstance(evidence, list):
            evidence_items = [
                f"<li>{escape(str(value))}</li>"
                for value in evidence
            ]
        else:
            evidence_items = [
                f"<li>{escape(str(evidence))}</li>"
            ]

        confidence_class = confidence.lower()
        if confidence_class not in ("high", "medium", "low"):
            confidence_class = "unknown"

        cards.append(
            '<article class="tech-card">'
            '<div class="tech-card-top">'
            f'<span class="tech-category">{category}</span>'
            f'<span class="tech-confidence {confidence_class}">'
            f'{escape(confidence)}</span>'
            '</div>'
            f'<h3>{name}</h3>'
            f'<p class="tech-version">Version: <strong>{version}</strong></p>'
            '<div class="tech-evidence-title">Detection evidence</div>'
            f'<ul>{"".join(evidence_items)}</ul>'
            '</article>'
        )

    count = len(cards)

    if not cards:
        content = (
            '<div class="tech-empty">'
            '<div class="tech-empty-icon">&#128269;</div>'
            '<h3>No technologies confirmed</h3>'
            '<p>No matching fingerprints were found in the fetched page response.</p>'
            '<small>This does not mean the website has no framework, language or CMS. '
            'Some technologies may be hidden or loaded outside the scanned response.</small>'
            '</div>'
        )
    else:
        content = '<div class="tech-grid">' + "".join(cards) + '</div>'

    return (
        '<section class="technology-section">'
        '<div class="tech-heading">'
        '<div><span class="tech-eyebrow">WEBSITE INTELLIGENCE</span>'
        '<h2>Technology Stack</h2>'
        '<p>Technologies identified from publicly exposed fingerprints.</p></div>'
        f'<div class="tech-total"><strong>{count}</strong>'
        '<span>Detected</span></div>'
        '</div>'
        f'{content}'
        '<p class="tech-disclaimer">Versions are displayed only when exposed by the website. '
        'Undetected or hidden technologies are not assumed.</p>'
        '</section>'
    )


def _render_technical_details(result):
    if not isinstance(result, dict):
        return (
            '<section class="detail-section">'
            '<h2>Security Findings</h2>'
            '<p>No technical details available.</p></section>'
        )

    findings = result.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    rows = []
    for item in findings:
        if not isinstance(item, dict):
            continue

        severity = str(item.get("severity", "info")).lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "info"

        rows.append(
            '<tr>'
            f'<td>{escape(str(item.get("finding", "Unnamed finding")))}</td>'
            f'<td><span class="severity severity-{severity}">'
            f'{escape(severity.upper())}</span></td>'
            f'<td>{escape(str(item.get("remediation", "Review manually")))}</td>'
            '</tr>'
        )

    findings_table = "".join(rows) or (
        '<tr><td colspan="3">No findings recorded.</td></tr>'
    )

    score_data = result.get("security_score", {})
    if isinstance(score_data, dict):
        score = score_data.get("score", "N/A")
    else:
        score = score_data if score_data is not None else "N/A"

    return (
        '<section class="detail-section">'
        '<h2>Security Findings</h2>'
        f'<p class="detail-score">Security Score: {escape(str(score))}/100</p>'
        '<div class="table-wrap"><table class="findings-table">'
        '<thead><tr><th>Finding</th><th>Severity</th>'
        '<th>Recommended Remediation</th></tr></thead>'
        f'<tbody>{findings_table}</tbody>'
        '</table></div></section>'
    )
@router.get(
    "/admin/security-scans/{scan_id}",
    response_class=HTMLResponse,
)
def admin_view_security_scan(
    scan_id: int,
    admin=Depends(verify_admin_session),
):
    if scan_id < 1:
        raise HTTPException(status_code=404, detail="Scan not found.")

    with get_connection() as connection:
        scan = connection.execute(
            "SELECT * FROM security_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    try:
        findings = json.loads(scan["findings_json"] or "[]")
        if not isinstance(findings, list):
            findings = []
    except (TypeError, ValueError):
        findings = []

    result = None
    if scan["result_json"]:
        try:
            parsed = json.loads(scan["result_json"])
            if isinstance(parsed, dict):
                result = parsed
        except (TypeError, ValueError):
            result = None

    rows = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('finding') or item.get('title') or item.get('name') or 'Finding'))}</td>"
            f"<td>{escape(str(item.get('severity', 'N/A')))}</td>"
            f"<td>{escape(str(item.get('description') or item.get('evidence') or 'No description saved.'))}</td>"
            f"<td>{escape(str(item.get('remediation') or 'No remediation details saved.'))}</td>"
            "</tr>"
        )

    if not rows:
        rows.append('<tr><td colspan="4">No findings were recorded.</td></tr>')

    technical_html = _render_technical_details(result)

    technology_html = _render_technology_section(result)

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PhishGuard Pro - Scan {scan_id}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background:#f4f6f9;
                   color:#202938; margin:0; padding:30px; }}
            main {{ max-width:1100px; margin:auto; background:white;
                    padding:28px; border-radius:12px; }}
            table {{ width:100%; border-collapse:collapse; margin-top:18px; }}
            th,td {{ padding:12px; border:1px solid #ddd; text-align:left; }}
            th {{ background:#edf2f7; }}
            pre {{ white-space:pre-wrap; overflow-wrap:anywhere;
                   background:#f3f5f7; padding:16px; border-radius:8px; }}
            a {{ color:#1457a6; }}

            .technology-section {{
                margin: 28px 0;
                padding: 24px;
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 16px;
            }}
            .tech-heading {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 16px;
                margin-bottom: 22px;
            }}
            .tech-eyebrow {{
                color: #2563eb;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1.4px;
            }}
            .tech-heading h2 {{
                margin: 7px 0;
                font-size: 24px;
            }}
            .tech-heading p, .tech-disclaimer {{
                color: #64748b;
                font-size: 13px;
            }}
            .tech-total {{
                min-width: 85px;
                padding: 12px;
                text-align: center;
                background: #eff6ff;
                border-radius: 12px;
            }}
            .tech-total strong, .tech-total span {{
                display: block;
            }}
            .tech-total strong {{
                color: #1d4ed8;
                font-size: 27px;
            }}
            .tech-total span {{
                color: #475569;
                font-size: 11px;
            }}
            .tech-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
                gap: 14px;
            }}
            .tech-card {{
                padding: 18px;
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                min-width: 0;
            }}
            .tech-card-top {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 8px;
            }}
            .tech-category, .tech-confidence {{
                padding: 5px 9px;
                border-radius: 20px;
                font-size: 11px;
                font-weight: 600;
            }}
            .tech-category {{
                background: #e0e7ff;
                color: #3730a3;
            }}
            .tech-confidence.high {{
                background: #dcfce7;
                color: #166534;
            }}
            .tech-confidence.medium {{
                background: #fef3c7;
                color: #92400e;
            }}
            .tech-confidence.low, .tech-confidence.unknown {{
                background: #f1f5f9;
                color: #475569;
            }}
            .tech-card h3 {{
                margin: 17px 0 8px;
                font-size: 18px;
            }}
            .tech-version {{
                color: #64748b;
                font-size: 13px;
            }}
            .tech-version strong {{
                color: #334155;
            }}
            .tech-evidence-title {{
                margin-top: 17px;
                font-size: 12px;
                font-weight: 700;
                color: #334155;
            }}
            .tech-card ul {{
                padding-left: 18px;
                margin-bottom: 0;
                color: #64748b;
                font-size: 12px;
                overflow-wrap: anywhere;
            }}
            .tech-card li {{
                margin-top: 6px;
            }}
            .tech-empty {{
                padding: 30px 18px;
                text-align: center;
                background: #f8fafc;
                border: 1px dashed #cbd5e1;
                border-radius: 12px;
            }}
            .tech-empty-icon {{
                font-size: 30px;
            }}
            .tech-empty h3 {{
                margin: 10px 0;
            }}
            .tech-empty p {{
                color: #475569;
            }}
            .tech-empty small {{
                display: block;
                max-width: 580px;
                margin: auto;
                color: #64748b;
                line-height: 1.6;
            }}
            .tech-disclaimer {{
                margin: 18px 0 0;
                line-height: 1.6;
            }}


        .period-filter {{ display:flex;align-items:center;gap:10px;margin-left:auto; }}
        .period-filter label {{ font-size:12px;color:#71809a;font-weight:700; }}
        .period-filter select {{ min-width:155px;padding:10px 34px 10px 12px;border:1px solid #dce3ef;border-radius:9px;background:#fff;color:#17233d;font-size:13px;font-weight:600;cursor:pointer; }}
        @media(max-width:760px) {{ .period-filter {{ margin:10px 0;width:100%; }} .period-filter select {{ flex:1; }} }}
      </style>
    </head>
    <body>
    <main>
        <h1>Website Security Scan Details</h1>
        <p><strong>Scan ID:</strong> {escape(str(scan["id"]))}</p>
        <p><strong>Website:</strong> {escape(str(scan["target_url"]))}</p>
        <p><strong>Hostname:</strong> {escape(str(scan["hostname"]))}</p>
        <p><strong>Security Score:</strong> {escape(str(scan["security_score"]))}/100</p>
        <p><strong>Grade:</strong> {escape(str(scan["grade"]))}</p>
        <p><strong>Risk Level:</strong> {escape(str(scan["risk_level"]).upper())}</p>
        <p><strong>Scan Date:</strong> {escape(str(scan["created_at"]))}</p>
        <h2>Findings and Remediation</h2>
        <table>
            <thead><tr>
                <th>Finding</th><th>Severity</th>
                <th>Description</th><th>Remediation</th>
            </tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
        {technology_html}
        {technical_html}
        <p><a href="/admin/dashboard">Back to Dashboard</a></p>
    </main>
    </body>
    </html>
    """)


@router.post("/admin/security-scan", response_class=HTMLResponse)
def admin_run_security_scan(
    url: str = Form(..., max_length=2048),
    authorized: str = Form(...),
    scan_mode: str = Form("fast"),
    admin=Depends(verify_admin_session),
    csrf=Depends(verify_admin_origin),
):
    if authorized != "yes":
        raise HTTPException(
            status_code=400,
            detail="Authorization confirmation is required."
        )

    try:
        result = analyze_website(url)
        scan_id = save_security_scan(result)

        score_data = result.get("security_score", {})
        if isinstance(score_data, dict):
            score = score_data.get("score", "N/A")
            grade = score_data.get("grade", "N/A")
            breakdown = score_data.get("breakdown", {})
        else:
            score = score_data
            grade = result.get("grade", "N/A")
            breakdown = {}

        findings = result.get("findings", [])
        finding_rows = []

        for item in findings:
            if not isinstance(item, dict):
                continue
            finding_rows.append(
                "<tr>"
            f"<td>{escape(str(item.get('finding') or item.get('title') or item.get('name') or 'Finding'))}</td>"
                f"<td>{escape(str(item.get('severity', 'N/A')))}</td>"
                f"<td>{escape(str(item.get('description', item.get('evidence', 'Security weakness detected.'))))}</td>"
                f"<td>{escape(str(item.get('remediation', 'Review and remediate this finding.')))}</td>"
                "</tr>"
            )

        if not finding_rows:
            finding_rows.append(
                '<tr><td colspan="4">No findings reported.</td></tr>'
            )

        details_html = _render_technical_details(result)
        technology_html = _render_technology_section(result)

        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>PhishGuard Pro - Scan Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; background:#f4f6f9;
                       color:#202938; margin:0; padding:30px; }}
                main {{ max-width:1100px; margin:auto; background:white;
                        padding:28px; border-radius:12px; }}
                .score {{ font-size:32px; font-weight:bold; }}
                table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
                th,td {{ padding:12px; border:1px solid #ddd; text-align:left; }}
                th {{ background:#edf2f7; }}
                pre {{ white-space:pre-wrap; overflow-wrap:anywhere;
                       background:#f3f5f7; padding:16px; border-radius:8px; }}
                a {{ color:#1457a6; }}

            .technology-section {{
                margin: 28px 0;
                padding: 24px;
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 16px;
            }}
            .tech-heading {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 16px;
                margin-bottom: 22px;
            }}
            .tech-eyebrow {{
                color: #2563eb;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1.4px;
            }}
            .tech-heading h2 {{
                margin: 7px 0;
                font-size: 24px;
            }}
            .tech-heading p, .tech-disclaimer {{
                color: #64748b;
                font-size: 13px;
            }}
            .tech-total {{
                min-width: 85px;
                padding: 12px;
                text-align: center;
                background: #eff6ff;
                border-radius: 12px;
            }}
            .tech-total strong, .tech-total span {{
                display: block;
            }}
            .tech-total strong {{
                color: #1d4ed8;
                font-size: 27px;
            }}
            .tech-total span {{
                color: #475569;
                font-size: 11px;
            }}
            .tech-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
                gap: 14px;
            }}
            .tech-card {{
                padding: 18px;
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                min-width: 0;
            }}
            .tech-card-top {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 8px;
            }}
            .tech-category, .tech-confidence {{
                padding: 5px 9px;
                border-radius: 20px;
                font-size: 11px;
                font-weight: 600;
            }}
            .tech-category {{
                background: #e0e7ff;
                color: #3730a3;
            }}
            .tech-confidence.high {{
                background: #dcfce7;
                color: #166534;
            }}
            .tech-confidence.medium {{
                background: #fef3c7;
                color: #92400e;
            }}
            .tech-confidence.low, .tech-confidence.unknown {{
                background: #f1f5f9;
                color: #475569;
            }}
            .tech-card h3 {{
                margin: 17px 0 8px;
                font-size: 18px;
            }}
            .tech-version {{
                color: #64748b;
                font-size: 13px;
            }}
            .tech-version strong {{
                color: #334155;
            }}
            .tech-evidence-title {{
                margin-top: 17px;
                font-size: 12px;
                font-weight: 700;
                color: #334155;
            }}
            .tech-card ul {{
                padding-left: 18px;
                margin-bottom: 0;
                color: #64748b;
                font-size: 12px;
                overflow-wrap: anywhere;
            }}
            .tech-card li {{
                margin-top: 6px;
            }}
            .tech-empty {{
                padding: 30px 18px;
                text-align: center;
                background: #f8fafc;
                border: 1px dashed #cbd5e1;
                border-radius: 12px;
            }}
            .tech-empty-icon {{
                font-size: 30px;
            }}
            .tech-empty h3 {{
                margin: 10px 0;
            }}
            .tech-empty p {{
                color: #475569;
            }}
            .tech-empty small {{
                display: block;
                max-width: 580px;
                margin: auto;
                color: #64748b;
                line-height: 1.6;
            }}
            .tech-disclaimer {{
                margin: 18px 0 0;
                line-height: 1.6;
            }}

            </style>
        </head>
        <body>
        <main>
            <h1>Website Security Scan Results</h1>
            <p>Scan ID: {scan_id}</p>
<p>Scan mode: {escape(str(result.get("scan_mode", "fast")).title())}</p>
            <p>Website: {escape(str(result.get("url", url)))}</p>
            <p class="score">Security Score: {escape(str(score))}/100</p>
            <p>Grade: {escape(str(grade))}</p>
            <p>Risk Level: {escape(str(result.get("risk_level", "N/A")))}</p>
            <p>HTTP Status: {escape(str(result.get("http_status", "N/A")))}</p>
            <h2>Findings and Remediation</h2>
            <table>
                <tr><th>Finding</th><th>Severity</th>
                    <th>Description</th><th>Remediation</th></tr>
                {''.join(finding_rows)}
            </table>
            {technology_html}
            <h2>Technical Details</h2>
            {details_html}
            <p><a href="/admin/dashboard">Back to Admin Dashboard</a></p>
        </main>
        </body>
        </html>
        """)

    except Exception as error:
        safe_error = escape(f"{type(error).__name__}: {error}")
        return HTMLResponse(
            "<h2>Scan could not be completed.</h2>"
            f"<p><strong>Reason:</strong> {safe_error}</p>"
            '<p><a href="/admin/dashboard">Back to Dashboard</a></p>',
            status_code=400,
        )



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


@router.post(
    "/admin/login",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_origin)],
)
def admin_login(
    request: Request,
    password: str = Form(..., max_length=1024),
):
    check_login_allowed(request)

    try:
        valid_credentials = verify_admin_credentials(password)
    except HTTPException:
        raise

    if not valid_credentials:
        record_login_failure(request)
        return HTMLResponse(
            content=_login_page("Invalid username or password."),
            status_code=401,
            headers={"Cache-Control": "no-store"},
        )

    clear_login_failures(request)
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
    verify_admin_origin(request)
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
    dependencies=[Depends(verify_admin_session), Depends(verify_admin_origin)],
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
    dependencies=[Depends(verify_admin_session), Depends(verify_admin_origin)],
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




_RED_TEAM_SERVICES = (
    ("facebook", "Facebook"),
    ("instagram", "Instagram"),
    ("tiktok", "TikTok"),
    ("snapchat", "Snapchat"),
    ("paypal", "PayPal"),
    ("google", "Google"),
    ("microsoft", "Microsoft"),
    ("netflix", "Netflix"),
    ("linkedin", "LinkedIn"),
    ("x", "X"),
    ("amazon", "Amazon"),
    ("apple", "Apple"),
    ("discord", "Discord"),
    ("telegram", "Telegram"),
    ("steam", "Steam"),
    ("spotify", "Spotify"),
    ("yahoo", "Yahoo"),
    ("reddit", "Reddit"),
    ("pinterest", "Pinterest"),
    ("twitch", "Twitch"),
    ("zoom", "Zoom"),
    ("dropbox", "Dropbox"),
    ("github", "GitHub"),
)


@router.get(
    "/admin/phishing-links",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_phishing_links():
    cards = "".join(
        f'<article class="service-card">'
        f'<h3>{escape(name)}</h3>'
        '<p>Red Team workspace</p>'
        f'<a class="service-link" href="/admin/phishing-links/{slug}">'
        'Open service page →</a></article>'
        for slug, name in _RED_TEAM_SERVICES
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Links | PhishGuard Pro</title>
<style>
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 32px; background: #f5f7fb;
       color: #17233d; font-family: Arial, sans-serif; }}
header {{ display: flex; justify-content: space-between;
          align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 28px; }}
h1 {{ margin: 0 0 8px; font-size: 27px; }}
.subtitle {{ color: #64748b; }}
.back {{ color: #2457c5; text-decoration: none; font-weight: 600; }}
.services {{ display: grid; grid-template-columns:
             repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; }}
.service-card {{ background: white; border: 1px solid #e2e8f0;
                 border-radius: 12px; padding: 20px; }}
.service-card h3 {{ margin: 0 0 12px; }}
.service-card p {{ color: #64748b; margin: 0 0 16px; }}
.service-link {{ display: inline-block; color: #2457c5;
                 text-decoration: none; font-weight: 600; }}
.notice {{ margin: 20px 0; padding: 14px 16px; background: #eff6ff;
           border: 1px solid #bfdbfe; border-radius: 10px; color: #1e40af; }}
</style>
</head>
<body>
<header>
<div><h1>Phishing Links</h1>
<div class="subtitle">Authorized Red Team service workspaces</div></div>
<nav>
<a class="back" href="/admin/link-generator/analytics">Date-wise Analytics</a>
&nbsp; | &nbsp;
<a class="back" href="/admin/dashboard">Back to Dashboard</a>
</nav>
</header>
<div class="notice">Authorized Red Team operations. Use only approved targets and test accounts.</div>
<div class="services">{cards}</div>
</body>
</html>"""

    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


@router.get(
    "/admin/phishing-links/{service_slug}",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_phishing_service(service_slug: str):
    services = dict(_RED_TEAM_SERVICES)
    service_name = services.get(service_slug)

    if service_name is None:
        raise HTTPException(status_code=404, detail="Red Team service not found")

    safe_name = escape(service_name)

    if service_slug == "facebook":
        options = [
            {
                "id": "page_access",
                "title": "Facebook Page Access Review",
                "checks": [
                    "Review administrators and assigned Page roles.",
                    "Remove outdated or unrecognized access.",
                    "Confirm that critical actions require authorized approval.",
                    "Review recent Page management activity.",
                ],
            },
            {
                "id": "business",
                "title": "Meta Business Portfolio Audit",
                "checks": [
                    "Review people and partner assignments.",
                    "Check connected business assets.",
                    "Review administrator privileges.",
                    "Confirm ownership of connected Pages and ad accounts.",
                ],
            },
            {
                "id": "recovery",
                "title": "Account Recovery Readiness",
                "checks": [
                    "Confirm recovery email and phone are controlled by the owner.",
                    "Review available multi-factor authentication methods.",
                    "Check that recovery methods are current.",
                    "Document the official account recovery procedure.",
                ],
            },
            {
                "id": "impersonation",
                "title": "Impersonation & Brand Protection",
                "checks": [
                    "Document suspicious profiles using public information.",
                    "Compare profile names and public business details.",
                    "Preserve relevant public URLs as evidence.",
                    "Use the official reporting process where appropriate.",
                ],
            },
            {
                "id": "profile",
                "title": "Public Profile Security Review",
                "checks": [
                    "Review publicly visible profile information.",
                    "Check audience and post visibility settings.",
                    "Review public contact and business details.",
                    "Document unnecessary public exposure.",
                ],
            },
        ]

        page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Facebook Security Review Workspace</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f3f6fb;color:#18243b;font-family:Inter,Arial,sans-serif}
header{background:#fff;border-bottom:1px solid #e3eaf4;padding:22px 5%;display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}
.brand{font-size:20px;font-weight:750;color:#1877f2}
a{color:#1877f2;text-decoration:none;font-weight:600}
main{max-width:1120px;margin:32px auto;padding:0 20px}
h1{font-size:30px;margin:0 0 8px}
.muted{color:#687891;line-height:1.6}
.hero{background:linear-gradient(120deg,#e8f1ff,#f7faff);border:1px solid #d8e6fb;border-radius:16px;padding:25px;margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}
.card,.panel{background:#fff;border:1px solid #e3eaf4;border-radius:13px;padding:20px}
.card h3{font-size:17px;margin:0 0 9px}
.card p{font-size:14px;color:#687891;line-height:1.55;min-height:44px}
button{background:#1877f2;color:white;border:0;padding:12px 17px;border-radius:8px;font-weight:650;cursor:pointer}
button:hover{background:#1264d8}
.panel{margin-top:22px}
label{display:block;font-weight:600;margin:14px 0 7px}
select,input{width:100%;padding:12px;border:1px solid #cbd6e5;border-radius:8px;font:inherit;background:#fff}
.result{margin-top:18px;padding:17px;background:#f5f8fd;border:1px solid #e1e9f4;border-radius:10px;display:none}
.result li{margin:10px 0;line-height:1.5;color:#40516b}
.notice{padding:14px;background:#fff8e8;border:1px solid #f2dfb2;border-radius:10px;color:#75551c;line-height:1.6;margin-top:18px}
@media(max-width:600px){header{padding:18px}main{margin:20px auto;padding:0 14px}h1{font-size:25px}}
</style>
</head>
<body>
<header>
<div class="brand">Facebook Security Review</div>
</header>
<main>
<section class="hero">
<h1>Facebook Red Team Workspace</h1>
<p class="muted">Service-specific security assessment workspace for Facebook Pages, public profiles and Meta business assets.</p>
<a href="https://www.facebook.com/security/" target="_blank" rel="noopener noreferrer">Official Facebook Security Center ↗</a>
</section>

<section class="grid" id="modules"></section>

<section class="panel">
<h2>Local Assessment Simulator</h2>
<p class="muted">Select an assessment module. Results are generated in this browser only; no information is submitted or stored.</p>
<form id="assessment">
<label for="module">Assessment module</label>
<select id="module" required></select>
<label for="asset">Asset reference (optional URL or internal test label)</label>
<input id="asset" maxlength="200" placeholder="Example: Owned Facebook Page / internal asset reference">
<p><button type="submit">Run Local Checklist</button></p>
</form>
<div class="result" id="result" aria-live="polite"></div>
</section>

<div class="notice"><strong>Local simulation:</strong> This workspace does not imitate Facebook sign-in, request passwords or verification codes, contact Facebook APIs, or transmit assessment data.</div>

</main>
<script>
const modules = __OPTIONS_JSON__;
const cards = document.getElementById("modules");
const select = document.getElementById("module");

for (const item of modules) {
  const option = document.createElement("option");
  option.value = item.id;
  option.textContent = item.title;
  select.appendChild(option);

  const card = document.createElement("article");
  card.className = "card";
  const heading = document.createElement("h3");
  heading.textContent = item.title;
  const description = document.createElement("p");
  description.textContent = item.checks.length + " review checkpoints";
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Select module";
  button.addEventListener("click", () => {
    select.value = item.id;
    document.getElementById("assessment").scrollIntoView({behavior:"smooth"});
  });
  card.append(heading, description, button);
  cards.appendChild(card);
}

document.getElementById("assessment").addEventListener("submit", event => {
  event.preventDefault();
  const item = modules.find(entry => entry.id === select.value);
  if (!item) return;

  const result = document.getElementById("result");
  result.replaceChildren();

  const heading = document.createElement("h3");
  heading.textContent = item.title + " — Local Checklist";
  result.appendChild(heading);

  const reference = document.getElementById("asset").value.trim();
  if (reference) {
    const label = document.createElement("p");
    label.textContent = "Asset reference: " + reference;
    result.appendChild(label);
  }

  const list = document.createElement("ul");
  for (const check of item.checks) {
    const li = document.createElement("li");
    li.textContent = "Review: " + check;
    list.appendChild(li);
  }
  result.appendChild(list);

  const note = document.createElement("p");
  note.textContent = "Simulation complete. No network request or data storage occurred.";
  result.appendChild(note);
  result.style.display = "block";
});
</script>
</body>
</html>"""

        page = page.replace("__OPTIONS_JSON__", json.dumps(options))
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    config = SERVICE_WORKSPACES.get(service_slug)
    if config is None:
        raise HTTPException(
            status_code=500,
            detail="Service workspace configuration missing",
        )

    page = render_service_workspace(service_name, config)
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})



@router.get(
    "/admin/new-scan",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_new_scan():
    return HTMLResponse("""
    <!doctype html><html lang="en"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishGuard Pro - New Scan</title>
    <style>
    body{font-family:Arial;background:#f4f6f9;color:#202938;margin:0;padding:35px}
    main{max-width:760px;margin:auto;background:white;padding:30px;border-radius:14px}
    input{box-sizing:border-box;width:100%;padding:13px;margin:10px 0 18px;border:1px solid #ccd5e2;border-radius:8px}
    button{background:#2458dc;color:white;border:0;padding:13px 22px;border-radius:8px;cursor:pointer}
    a{color:#2458dc} .note{background:#f1f5ff;padding:14px;border-radius:8px;line-height:1.5}
    </style></head><body><main>
    <h1>New Website Security Scan</h1>
    <p>Run a security assessment on a website you own or are authorized to test.</p>
    <form method="post" action="/admin/security-scan">
      <label for="url">Website URL</label>
      <input id="url" name="url" type="url" placeholder="https://example.com" maxlength="2048" required>
      <label><input type="checkbox" name="authorized" value="yes" required style="width:auto">
      I confirm I own this website or have explicit permission to test it.</label>
      <p><button type="submit">Start Security Scan</button></p>
    </form>
    <p class="note">Only scan authorized targets. Scan results will be saved in Scan Reports.</p>
    <p><a href="/admin/dashboard">Back to Dashboard</a></p>
    </main></body></html>
    """)



@router.post("/admin/full-scan/run", response_class=HTMLResponse)
def admin_run_full_scan(
    url: str = Form(..., max_length=2048),
    authorized: str = Form(...),
    admin=Depends(verify_admin_session),
    csrf=Depends(verify_admin_origin),
):
    if authorized != "yes":
        raise HTTPException(status_code=400, detail="Authorization confirmation is required.")

    try:
        result = analyze_full_website(url, scan_mode=scan_mode)
        scan_id = save_security_scan(result)
    except (ValueError, RuntimeError) as error:
        return HTMLResponse(
            "<h1>Full Scan could not be completed</h1>"
            f"<p>{escape(str(error))}</p>"
            "<a href='/admin/full-scan'>Return</a>",
            status_code=400,
        )
    except Exception:
        return HTMLResponse(
            "<h1>Full Scan error</h1>"
            "<p>Unexpected error. Check application logs.</p>"
            "<a href='/admin/full-scan'>Return</a>",
            status_code=500,
        )

    score = result["security_score"]
    summary = result["summary"]

    rows = []
    for item in result["findings"]:
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('severity', '')).upper())}</td>"
            f"<td>{escape(str(item.get('finding', '')))}</td>"
            f"<td>{escape(str(item.get('remediation', 'Review finding.')))}</td>"
            "</tr>"
        )

    if not rows:
        rows.append("<tr><td colspan='3'>No findings reported.</td></tr>")

    checks = []
    for name, data in result.get("checks", {}).items():
        checks.append(
            '<section class="check-result">'
            f'<h3>{escape(name.replace("_", " ").title())}</h3>'
            f'{_render_structured_data(data)}'
            '</section>'
        )

    if not checks:
        checks.append('<p class="muted">No individual check data was returned.</p>')

    return HTMLResponse(f"""
    <!doctype html><html><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Full Scan Results</title>
    <style>
    body{{font-family:Arial;background:#f4f6f9;color:#202938;padding:25px}}
    main{{max-width:1100px;margin:auto;background:white;padding:25px;border-radius:12px}}
    table{{width:100%;border-collapse:collapse;margin:18px 0}}
    th,td{{padding:11px;border:1px solid #ddd;text-align:left;vertical-align:top}}
    th{{background:#edf2f7}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
    a{{color:#2458dc}}
    </style></head><body><main>
    <h1>Full Security Scan Results</h1>
    <p>Target: {escape(result['url'])}</p>
    <p>Scan ID: {scan_id}</p>
    <h2>Score: {score['score']}/100 — Grade {escape(score['grade'])}</h2>
    <p>Risk: {escape(result['risk_level'].upper())}</p>
    <h2>Subdomain Processing</h2>
    <p>Discovered: {result.get("checks", {}).get("subdomains", {}).get("total_discovered", 0)} |
    Processed: {result.get("checks", {}).get("subdomains", {}).get("total_processed", 0)} |
    Resolved: {result.get("checks", {}).get("subdomains", {}).get("total_resolved", 0)} |
    Unresolved: {result.get("checks", {}).get("subdomains", {}).get("total_unresolved", 0)} |
    Truncated: {result.get("checks", {}).get("subdomains", {}).get("truncated", False)}</p>
    <p>Critical: {summary.get('critical', 0)} |
    High: {summary.get('high', 0)} |
    Medium: {summary.get('medium', 0)} |
    Low: {summary.get('low', 0)} |
    Total: {summary.get('total', 0)}</p>
    <h2>Findings</h2>
    <table><tr><th>Severity</th><th>Finding</th><th>Remediation</th></tr>
    {''.join(rows)}</table>
    <h2>Individual Check Results</h2>
    {''.join(checks)}
    <p><a href="/admin/security-scans/{scan_id}">Open Saved Report</a></p>
    <p><a href="/admin/full-scan">Run Another Scan</a> |
    <a href="/admin/scan-reports">Scan Reports</a> |
    <a href="/admin/dashboard">Dashboard</a></p>
    </main></body></html>
    """)


@router.get(
    "/admin/full-scan",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_full_scan():
    return HTMLResponse("""
    <!doctype html><html lang="en"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishGuard Pro - Full Scan</title>
    <style>body{font-family:Arial;background:#f4f6f9;color:#202938;padding:35px}
    main{max-width:760px;margin:auto;background:white;padding:30px;border-radius:14px}
    a{color:#2458dc}</style></head><body><main>
    <h1>Full Security Scan</h1>
    <p>Run combined passive checks on a website you own or are authorized to test.</p>
    <form method="post" action="/admin/full-scan/run">
      <label for="url">Authorized HTTPS Website URL</label>
      <input id="url" name="url" type="url" maxlength="2048"
        placeholder="https://example.com" required
        style="box-sizing:border-box;width:100%;padding:13px;margin:12px 0">
      <label for="scan_mode">Scan depth</label>
      <select id="scan_mode" name="scan_mode"
        style="box-sizing:border-box;width:100%;padding:12px;margin:12px 0">
        <option value="fast" selected>Fast — up to 50 subdomains</option>
        <option value="extended">Extended — up to 200 subdomains</option>
        <option value="thorough">Thorough — up to 500 subdomains</option>
      </select>
      <p><label><input type="checkbox" name="authorized" value="yes" required>
      I confirm I own this website or have explicit permission to test it.</label></p>
      <button type="submit">Run Full Scan</button>
    </form>
    <p>Checks: HTTPS/TLS, security headers, technologies, cookies, SPF, DMARC and passive subdomain discovery.</p>
    <p>Results are saved automatically in Scan Reports.</p>
    <p><a href="/admin/new-scan">Open New Scan</a></p>
    <p><a href="/admin/dashboard">Back to Dashboard</a></p>
    </main></body></html>
    """)



@router.get(
    "/admin/web-importer",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_web_importer():
    return HTMLResponse("""
    <!doctype html><html lang="en"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishGuard Pro - Web Importer</title>
    <style>
    body{font-family:Arial;background:#f4f6f9;color:#202938;padding:25px}
    main{max-width:900px;margin:auto;background:white;padding:30px;border-radius:14px}
    input{box-sizing:border-box;width:100%;padding:12px;margin:10px 0 18px}
    button{padding:12px 20px;background:#2458dc;color:white;border:0;border-radius:7px;cursor:pointer}
    a{color:#2458dc}.note{color:#596579;font-size:14px}
    </style></head><body><main>
    <h1>Web Importer</h1>
    <p>Import an authorized website into a sanitized static preview.</p>
    <form method="post" action="/admin/web-importer/import">
      <label for="url"><strong>Authorized HTTPS Website</strong></label>
      <input id="url" name="url" type="url" maxlength="2048"
        placeholder="https://example.com" required>
      <p><label><input type="checkbox" name="authorized" value="yes"
        required style="width:auto">
        I confirm I own this website or have explicit permission to import it.</label></p>
      <button type="submit">Import Website</button>
    </form>
    <p class="note">Only domains configured in the server authorization allowlist can be imported.
    JavaScript is not executed and visitor credentials are not collected.</p>
    <p><a href="/admin/dashboard">Back to Dashboard</a></p>
    </main></body></html>
    """)


@router.post("/admin/web-importer/import", response_class=HTMLResponse)
def admin_import_website(
    url: str = Form(..., max_length=2048),
    authorized: str = Form(...),
    admin=Depends(verify_admin_session),
    csrf=Depends(verify_admin_origin),
):
    if authorized != "yes":
        raise HTTPException(
            status_code=400,
            detail="Authorization confirmation is required.",
        )

    try:
        authorization = validate_website_authorization(url)
        if not authorization.get("authorized"):
            raise ValueError("Website authorization was not approved.")

        result = import_website(url)
        preview_url = build_preview_url(result["preview_id"])
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except (RuntimeError, OSError) as error:
        raise HTTPException(
            status_code=502,
            detail="Website import failed due to a network or storage error.",
        ) from error

    website_html = escape(str(result.get("website", "")))
    preview_html = escape(preview_url)

    return HTMLResponse(f"""
    <!doctype html><html lang="en"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Web Import Result</title>
    <style>
    body{{font-family:Arial;background:#f4f6f9;color:#202938;padding:25px}}
    main{{max-width:850px;margin:auto;background:white;padding:30px;border-radius:14px}}
    .result{{padding:15px;background:#f1f5f9;border-radius:9px;margin:12px 0}}
    a{{color:#2458dc;overflow-wrap:anywhere}}
    </style></head><body><main>
    <h1>Website Import Completed</h1>
    <p><strong>Website:</strong> {website_html}</p>
    <p><strong>Status:</strong> {escape(str(result.get("status", "completed")))}</p>
    <div class="result">
      <p><strong>Preview:</strong> <a href="{preview_html}" target="_blank" rel="noopener noreferrer">{preview_html}</a></p>
      <p>Preview type: {escape(str(result.get("preview_type", "sanitized_static_html")))}</p>
      <p>Assets found: {int(result.get("assets_found", 0))}</p>
      <p>Assets imported: {int(result.get("assets_imported", 0))}</p>
      <p>Assets skipped: {int(result.get("assets_skipped", 0))}</p>
      <p>JavaScript executed: No</p>
      <p>Credentials collected: No</p>
    </div>
    <p><a href="/admin/web-importer">Import another website</a> |
    <a href="/admin/dashboard">Dashboard</a></p>
    </main></body></html>
    """)


@router.get(
    "/admin/scan-reports",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_scan_reports():
    with get_connection() as connection:
        scans = connection.execute(
            """
            SELECT id, hostname, target_url, security_score,
                   grade, risk_level, created_at
            FROM security_scans
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

    rows = []
    for scan in scans:
        rows.append(
            "<tr>"
            f'<td>{escape(str(scan["id"]))}</td>'
            f'<td>{escape(str(scan["hostname"] or "—"))}</td>'
            f'<td>{escape(str(scan["target_url"] or "—"))}</td>'
            f'<td>{escape(str(scan["security_score"] or "—"))}</td>'
            f'<td>{escape(str(scan["grade"] or "—"))}</td>'
            f'<td>{escape(str(scan["risk_level"] or "—"))}</td>'
            f'<td>{escape(str(scan["created_at"] or "—"))}</td>'
            f'<td><a href="/admin/security-scans/{int(scan["id"])}">View</a></td>'
            "</tr>"
        )

    table_rows = "".join(rows) or '<tr><td colspan="8">No saved scans yet.</td></tr>'

    return HTMLResponse(f"""
    <!doctype html><html lang="en"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishGuard Pro - Scan Reports</title>
    <style>
    body{{font-family:Arial;background:#f4f6f9;color:#202938;padding:30px}}
    main{{max-width:1200px;margin:auto;background:white;padding:25px;border-radius:14px;overflow:auto}}
    table{{width:100%;border-collapse:collapse;margin-top:20px}}
    th,td{{padding:12px;border-bottom:1px solid #e5eaf1;text-align:left;font-size:13px}}
    th{{background:#f1f5f9}} a{{color:#2458dc}}
    </style></head><body><main>
    <h1>Scan Reports</h1>
    <p>Saved website security assessments (latest 100 records).</p>
    <table><thead><tr>
    <th>ID</th><th>Hostname</th><th>Website</th><th>Score</th>
    <th>Grade</th><th>Risk</th><th>Date</th><th>Report</th>
    </tr></thead><tbody>{table_rows}</tbody></table>
    <p><a href="/admin/dashboard">Back to Dashboard</a></p>
    </main></body></html>
    """)



@router.get(
    "/admin/security-tools",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_security_tools():
    return HTMLResponse("""
    <!doctype html><html lang="en"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishGuard Pro - Security Tools</title>
    <style>
    body{font-family:Arial;background:#f4f6f9;color:#202938;padding:25px}
    main{max-width:900px;margin:auto;background:white;padding:30px;border-radius:14px}
    .tool{padding:17px;margin:12px 0;border:1px solid #dce3ed;border-radius:10px}
    input,select{box-sizing:border-box;width:100%;padding:12px;margin:9px 0 16px}
    button{padding:12px 20px;background:#2458dc;color:white;border:0;border-radius:7px;cursor:pointer}
    a{color:#2458dc}
    label{font-weight:bold}
    .note{color:#596579;font-size:14px}
    </style></head><body><main>
    <h1>Security Tools</h1>
    <p>Run an individual passive security check on a website you own or are authorized to test.</p>
    <form method="post" action="/admin/security-tools/run">
      <label for="url">Authorized HTTPS Website</label>
      <input id="url" name="url" type="url" maxlength="2048"
        placeholder="https://example.com" required>
      <label for="tool">Select Security Tool</label>
      <select id="tool" name="tool" required>
        <option value="tls">TLS / SSL Certificate Checker</option>
        <option value="headers">Security Headers Analyzer</option>
        <option value="dns">DNS / SPF / DMARC Checker</option>
        <option value="cookies">Cookie Security Analyzer</option>
        <option value="technology">Technology Detector</option>
        <option value="domain">Domain Intelligence (DNS / RDAP / IP)</option>
        <option value="network">IP &amp; Network Intelligence (ASN / PTR)</option>
        <option value="subdomains">Subdomain Discovery (Certificate Transparency)</option>
      </select>
      <p><label><input type="checkbox" name="authorized" value="yes"
        required style="width:auto"> I confirm I own this website or have explicit permission to test it.</label></p>
      <button type="submit">Run Selected Tool</button>
    </form>
    <div class="tool"><h3>TLS / SSL Checker</h3><p>Certificate validity, expiry and TLS version.</p></div>
    <div class="tool"><h3>Security Headers Analyzer</h3><p>Checks important browser security response headers.</p></div>
    <div class="tool"><h3>DNS / SPF / DMARC Checker</h3><p>Checks email domain authentication records.</p></div>
    <div class="tool"><h3>Cookie Security Analyzer</h3><p>Checks Secure, HttpOnly and SameSite cookie flags.</p></div>
    <div class="tool"><h3>Technology Detector</h3><p>Passively identifies technologies exposed by the website.</p></div>
    <p class="note">These are passive checks. No exploitation, brute force or destructive testing is performed.</p>
    <p><a href="/admin/full-scan">Full Scan</a> |
    <a href="/admin/scan-reports">Scan Reports</a> |
    <a href="/admin/dashboard">Dashboard</a></p>
    </main></body></html>
    """)


@router.post("/admin/security-tools/run", response_class=HTMLResponse)
def admin_run_security_tool(
    url: str = Form(..., max_length=2048),
    tool: str = Form(...),
    authorized: str = Form(...),
    admin=Depends(verify_admin_session),
    csrf=Depends(verify_admin_origin),
):
    if authorized != "yes":
        raise HTTPException(status_code=400, detail="Authorization confirmation is required.")

    tool_names = {
        "tls": ("TLS / SSL Certificate Checker", "tls"),
        "headers": ("Security Headers Analyzer", "headers"),
        "dns": ("DNS / SPF / DMARC Checker", "dns"),
        "cookies": ("Cookie Security Analyzer", "cookies"),
        "technology": ("Technology Detector", "technologies"),
    }

    if tool == "subdomains":
        try:
            parsed, hostname = validate_target_url(url)
            result = discover_subdomains(hostname)
            rendered = _render_subdomain_discovery(result)

            return HTMLResponse(f"""
            <!doctype html><html lang="en"><head><meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Subdomain Discovery - PhishGuard Pro</title>
            <style>
            body{{font-family:Arial,sans-serif;background:#f4f6f9;color:#202938;padding:24px}}
            main{{max-width:1100px;margin:auto;background:white;padding:28px;border-radius:14px}}
            table{{width:100%;border-collapse:collapse;margin-top:20px}}
            th,td{{padding:12px;text-align:left;border-bottom:1px solid #e8edf3;overflow-wrap:anywhere}}
            th{{background:#f1f5f9}} a{{color:#2458dc;text-decoration:none}}
            .meta{{color:#596579;line-height:1.8}}
            </style></head><body><main>
            <h1>Subdomain Discovery</h1>
            <p class="meta"><strong>Target:</strong> {escape(url)}<br>
            <strong>Domain:</strong> {escape(hostname)}<br>
            <strong>Discovery source:</strong> Certificate Transparency<br>
            <strong>Discovered:</strong> {result["total_discovered"]}<br>
            <strong>Currently DNS-resolved:</strong> {result["total_resolved"]}<br>
            <strong>Source status:</strong> {escape(result["source_status"])}</p>
            {rendered}
            <p class="meta">Certificate records are historical evidence. DNS resolution indicates current public DNS data; unresolved names are not confirmed active assets.</p>
            <p><a href="/admin/security-tools">Run Another Tool</a> |
            <a href="/admin/full-scan">Full Scan</a> |
            <a href="/admin/dashboard">Dashboard</a></p>
            </main></body></html>
            """)

        except (ValueError, RuntimeError, OSError) as error:
            return HTMLResponse(
                "<h1>Subdomain Discovery could not complete</h1>"
                f"<p>{escape(str(error))}</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=400,
            )
        except Exception:
            return HTMLResponse(
                "<h1>Subdomain Discovery Error</h1>"
                "<p>Unexpected error. Check application logs.</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=500,
            )

    if tool == "network":
        try:
            import socket

            parsed, hostname = validate_target_url(url)
            resolved = socket.getaddrinfo(
                hostname, None, type=socket.SOCK_STREAM
            )
            addresses = sorted({
                item[4][0] for item in resolved
            })

            results = analyze_network_addresses(addresses)
            rendered = _render_network_intelligence(results)

            return HTMLResponse(f"""
            <!doctype html><html lang="en"><head><meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>IP &amp; Network Intelligence - PhishGuard Pro</title>
            <style>
            body{{font-family:Arial,sans-serif;background:#f4f6f9;color:#202938;padding:24px}}
            main{{max-width:1100px;margin:auto;background:white;padding:28px;border-radius:14px}}
            section{{margin:22px 0;padding:18px;border:1px solid #e1e7ef;border-radius:10px}}
            table{{width:100%;border-collapse:collapse}}
            th,td{{padding:11px;text-align:left;border-bottom:1px solid #e8edf3;overflow-wrap:anywhere}}
            th{{width:30%;color:#596579;background:#f8fafc}}
            h1{{margin-bottom:8px}} a{{color:#2458dc;text-decoration:none}}
            .meta{{color:#596579;line-height:1.8}}
            .tag{{display:inline-block;background:#edf3ff;color:#2458dc;padding:6px 10px;border-radius:20px;font-size:12px}}
            </style></head><body><main>
            <span class="tag">PASSIVE NETWORK ASSESSMENT</span>
            <h1>IP &amp; Network Intelligence</h1>
            <p class="meta"><strong>Target:</strong> {escape(url)}<br>
            <strong>Hostname:</strong> {escape(hostname)}<br>
            <strong>Resolved IP addresses:</strong> {len(addresses)}</p>
            {rendered}
            <p class="meta">Network information is based on public ASN and reverse DNS records.</p>
            <p><a href="/admin/security-tools">Run Another Tool</a> |
            <a href="/admin/full-scan">Full Scan</a> |
            <a href="/admin/dashboard">Dashboard</a></p>
            </main></body></html>
            """)

        except (ValueError, RuntimeError, OSError, socket.gaierror) as error:
            return HTMLResponse(
                "<h1>Network Intelligence could not complete</h1>"
                f"<p>{escape(str(error))}</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=400,
            )
        except Exception:
            return HTMLResponse(
                "<h1>Network Intelligence Error</h1>"
                "<p>Unexpected error. Check application logs.</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=500,
            )


    if tool == "dns":
        try:
            parsed, hostname = validate_target_url(url)
            result = analyze_dns_security(hostname)
            rendered = _render_dns_security(result)

            return HTMLResponse(f"""
            <!doctype html><html lang="en"><head><meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>DNS Security Assessment - PhishGuard Pro</title>
            <style>
            body{{font-family:Arial,sans-serif;background:#f4f6f9;color:#202938;padding:24px}}
            main{{max-width:1150px;margin:auto;background:white;padding:28px;border-radius:14px}}
            section{{margin:22px 0;padding:18px;border:1px solid #e1e7ef;border-radius:10px}}
            h1{{margin-bottom:8px}} h2{{font-size:18px;margin-top:0}}
            table{{width:100%;border-collapse:collapse}}
            th,td{{padding:11px;text-align:left;border-bottom:1px solid #e8edf3;
            overflow-wrap:anywhere;font-size:13px;vertical-align:top}}
            th{{background:#f1f5f9}} .muted{{color:#718096}}
            .meta{{color:#596579;line-height:1.8}}
            .status{{color:#596579;font-size:13px}}
            .summary{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}}
            .summary div{{background:#f1f5f9;padding:16px;border-radius:9px}}
            .summary strong,.summary span{{display:block}}
            .summary strong{{font-size:24px;margin-bottom:5px}}
            .summary span{{font-size:12px;color:#596579}}
            a{{color:#2458dc;text-decoration:none}}
            @media(max-width:650px){{.summary{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}
            </style></head><body><main>
            <h1>DNS Security Assessment</h1>
            <p class="meta"><strong>Target:</strong> {escape(url)}<br>
            <strong>Domain:</strong> {escape(hostname)}<br>
            <strong>Assessment:</strong> Passive DNS checks</p>
            {rendered}
            <p class="meta">DKIM is checked only when a selector is supplied. No selector is guessed.</p>
            <p><a href="/admin/security-tools">Run Another Tool</a> |
            <a href="/admin/full-scan">Full Scan</a> |
            <a href="/admin/dashboard">Dashboard</a></p>
            </main></body></html>
            """)

        except (ValueError, RuntimeError, OSError) as error:
            return HTMLResponse(
                "<h1>DNS Security Assessment could not complete</h1>"
                f"<p>{escape(str(error))}</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=400,
            )
        except Exception:
            return HTMLResponse(
                "<h1>DNS Security Assessment Error</h1>"
                "<p>Unexpected error. Check application logs.</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=500,
            )

    if tool == "domain":
        try:
            parsed, hostname = validate_target_url(url)
            result = analyze_domain_intelligence(hostname)
            rendered = _render_domain_intelligence(result)
            target_url = escape(url)
            safe_hostname = escape(hostname)

            return HTMLResponse(f"""
            <!doctype html><html lang="en"><head><meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Domain Intelligence - PhishGuard Pro</title>
            <style>
            body{{font-family:Arial,sans-serif;background:#f4f6f9;color:#202938;padding:24px}}
            main{{max-width:1100px;margin:auto;background:white;padding:28px;border-radius:14px}}
            section{{margin:24px 0;padding:18px;border:1px solid #e1e7ef;border-radius:10px}}
            h1{{margin-bottom:8px}} h2{{font-size:19px;margin-top:0}}
            table{{width:100%;border-collapse:collapse}}
            td{{padding:11px;border-bottom:1px solid #e8edf3;overflow-wrap:anywhere;font-size:14px}}
            tr:last-child td{{border-bottom:0}}
            .muted{{color:#718096}}
            .meta{{color:#596579;line-height:1.7}}
            a{{color:#2458dc;text-decoration:none}}
            .tag{{display:inline-block;background:#edf3ff;color:#2458dc;padding:6px 10px;border-radius:20px;font-size:12px}}
            </style></head><body><main>
            <span class="tag">PASSIVE DOMAIN ASSESSMENT</span>
            <h1>Domain Intelligence</h1>
            <div class="meta"><strong>Target:</strong> {target_url}<br>
            <strong>Hostname:</strong> {safe_hostname}<br>
            <strong>Data source:</strong> Public DNS records and RDAP</div>
            {rendered}
            Missing or undisclosed records are not treated as confirmed vulnerabilities.</p>
            <p><a href="/admin/security-tools">Run Another Tool</a> |
            <a href="/admin/full-scan">Full Scan</a> |
            <a href="/admin/dashboard">Dashboard</a></p>
            </main></body></html>
            """)

        except (ValueError, RuntimeError, OSError) as error:
            return HTMLResponse(
                "<h1>Domain Intelligence could not complete</h1>"
                f"<p>{escape(str(error))}</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=400,
            )
        except Exception:
            return HTMLResponse(
                "<h1>Domain Intelligence Error</h1>"
                "<p>Unexpected error. Check application logs.</p>"
                "<a href='/admin/security-tools'>Return to Security Tools</a>",
                status_code=500,
            )

    if tool not in tool_names:
        raise HTTPException(status_code=400, detail="Unknown security tool.")

    try:
        result = analyze_website(url)
        title, _ = tool_names[tool]

        result_fields = {
            "tls": "tls",
            "headers": "headers",
            "cookies": "cookie_security",
            "technology": "technologies",
        }
        details = result.get(result_fields[tool], {})
        if not details:
            details = {"message": "No data was returned for this check."}

        rendered = escape(json.dumps(details, indent=2, default=str))
        hostname = escape(str(result.get("hostname", "Unknown")))
        target_url = escape(str(result.get("url", url)))

        return HTMLResponse(f"""
        <!doctype html><html><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escape(title)} - Results</title>
        <style>
        body{{font-family:Arial;background:#f4f6f9;color:#202938;padding:25px}}
        main{{max-width:950px;margin:auto;background:white;padding:28px;border-radius:12px}}
        pre{{background:#f1f5f9;padding:18px;border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere}}
        a{{color:#2458dc}}
        </style></head><body><main>
        <h1>{escape(title)}</h1>
        <p><strong>Target:</strong> {target_url}</p>
        <p><strong>Hostname:</strong> {hostname}</p>
        <h2>Tool Results</h2>
        <pre>{rendered}</pre>
        <p>Assessment completed using passive security checks.</p>
        <p><a href="/admin/security-tools">Run Another Tool</a> |
        <a href="/admin/full-scan">Full Scan</a> |
        <a href="/admin/dashboard">Dashboard</a></p>
        </main></body></html>
        """)

    except (ValueError, RuntimeError, OSError) as error:
        return HTMLResponse(
            "<h1>Security Tool could not complete</h1>"
            f"<p>{escape(str(error))}</p>"
            "<a href='/admin/security-tools'>Return to Security Tools</a>",
            status_code=400,
        )
    except Exception:
        return HTMLResponse(
            "<h1>Security Tool Error</h1>"
            "<p>Unexpected error. Check application logs.</p>"
            "<a href='/admin/security-tools'>Return to Security Tools</a>",
            status_code=500,
        )


@router.get(
    "/admin/dashboard",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_dashboard(request: Request, message: str = "", period: str = "7d"):
    with get_connection() as connection:
        campaigns = connection.execute(
            """
            SELECT id, name, tracking_code, status, created_at
            FROM campaigns
            ORDER BY id DESC
            """
        ).fetchall()

        security_scans = connection.execute(
            """
            SELECT id, hostname, target_url, security_score,
                   grade, risk_level, findings_json, created_at
            FROM security_scans
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

        all_security_scans = connection.execute(
            """
            SELECT id, hostname, target_url, security_score,
                   grade, risk_level, findings_json, created_at
            FROM security_scans
            ORDER BY id DESC
            """
        ).fetchall()

    period = period if period in ("7d", "1m", "all") else "7d"
    now = dt.datetime.utcnow()
    days = 7 if period == "7d" else 30
    if period != "all":
        cutoff = now - dt.timedelta(days=days)
        filtered_scans = []
        for scan in all_security_scans:
            try:
                stamp = dt.datetime.fromisoformat(str(scan["created_at"]).replace("Z", "+00:00"))
                if stamp.tzinfo:
                    stamp = stamp.astimezone(dt.timezone.utc).replace(tzinfo=None)
                if stamp >= cutoff:
                    filtered_scans.append(scan)
            except (TypeError, ValueError):
                continue
    else:
        filtered_scans = list(all_security_scans)

    security_scans = filtered_scans[:20]
    period_filter_html = f"""
      <form method="get" action="/admin/dashboard" class="period-filter">
        <label for="period-select">Results period</label>
        <select id="period-select" name="period" onchange="this.form.submit()">
          <option value="7d" {"selected" if period == "7d" else ""}>Last 7 Days</option>
          <option value="1m" {"selected" if period == "1m" else ""}>Last 1 Month</option>
          <option value="all" {"selected" if period == "all" else ""}>All Time</option>
        </select>
      </form>
    """

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

        for participant in participants[:25]:
            if participant["completed"]:
                participant_status = "Completed"
            elif participant["consent_activity"]:
                participant_status = "In progress"
            else:
                participant_status = "Not tracked"

            ip_value = (
                participant["ip_address"]
                if participant["consent_ip"]
                else "Not consented"
            )
            browser_value = (
                " ".join(
                    value for value in (
                        participant["browser_name"],
                        participant["browser_version"],
                    ) if value
                )
                if participant["consent_device"]
                else "Not consented"
            )
            os_value = (
                participant["os_name"]
                if participant["consent_device"]
                else "Not consented"
            )
            device_value = (
                participant["device_type"]
                if participant["consent_device"]
                else "Not consented"
            )
            user_agent_value = (
                participant["user_agent"]
                if participant["consent_device"] and participant["user_agent"]
                else "Not consented"
            )

            recent_rows.append(
                f"""
                <tr>
                    <td>{escape(participant["participant_name"])}</td>
                    <td>{escape(str(participant["submitted_at"]))}</td>
                    <td>{escape(str(participant["total_events"]))}</td>
                    <td>{escape(participant_status)}</td>
                    <td>{escape(str(ip_value))}</td>
                    <td>{escape(str(browser_value))}</td>
                    <td>{escape(str(os_value))}</td>
                    <td>{escape(str(device_value))}</td>
                    <td title="{escape(str(user_agent_value), quote=True)}">{escape(str(user_agent_value))}</td>
                    <td>{escape(str(participant["last_activity"] or "No activity"))}</td>
                </tr>
                """
            )

        recent_table = (
            "\n".join(recent_rows)
            if recent_rows
            else '<tr><td colspan="10">No participants yet.</td></tr>'
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
                                <th>Public IP (consent)</th>
                                <th>Browser</th>
                                <th>Operating system</th>
                                <th>Device</th>
                                <th>User-Agent</th>
                                <th>Last activity</th>
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

    scan_rows = []

    for scan in security_scans:
        try:
            findings = json.loads(scan["findings_json"])
            finding_count = len(findings) if isinstance(findings, list) else 0
        except (TypeError, ValueError):
            finding_count = 0

        scan_rows.append(
            f"""
            <tr>
                <td>{escape(str(scan["id"]))}</td>
                <td>{escape(str(scan["hostname"]))}</td>
                <td><span class="score-circle { "score-good" if int(scan["security_score"] or 0) >= 80 else "score-warning" if int(scan["security_score"] or 0) >= 60 else "score-risk" }">{escape(str(scan["security_score"]))}</span></td>
                <td>{escape(str(scan["grade"]))}</td>
                <td>{escape(str(scan["risk_level"]).upper())}</td>
                <td>{finding_count}</td>
                <td>{escape(str(scan["created_at"]))}</td>
                <td><a href="/admin/security-scans/{escape(str(scan["id"]))}">View Details</a></td>
            </tr>
            """
        )

    scan_history = (
        "\n".join(scan_rows)
        if scan_rows
        else '<tr><td colspan="8">No security scans recorded yet.</td></tr>'
    )

    content = (
        "\n".join(campaign_cards)
        if campaign_cards
        else "<p>No campaigns available.</p>"
    )


    service_items = _RED_TEAM_SERVICES

    scores = [int(scan["security_score"] or 0) for scan in security_scans]
    average_score = round(sum(scores) / len(scores)) if scores else 0
    latest_score = scores[0] if scores else None
    latest_host = escape(str(security_scans[0]["hostname"])) if security_scans else "No scan yet"

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for scan in security_scans:
        try:
            items = json.loads(scan["findings_json"] or "[]")
        except (TypeError, ValueError):
            items = []
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    severity = str(item.get("severity", "info")).lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    else:
                        severity_counts["info"] += 1

    total_findings = sum(severity_counts.values())
    max_severity = max(severity_counts.values(), default=0) or 1
    severity_bars = "".join(
        f'<div class="bar-row"><span>{name.title()}</span>'
        f'<div class="bar-track"><i class="bar-{name}" style="width:{count / max_severity * 100:.1f}%"></i></div>'
        f'<strong>{count}</strong></div>'
        for name, count in severity_counts.items()
    )

    score_class = (
        "score-good" if latest_score is not None and latest_score >= 80
        else "score-warning" if latest_score is not None and latest_score >= 60
        else "score-risk"
    )
    score_html = (
        f'<div class="hero-score {score_class}"><strong>{latest_score}</strong><span>OUT OF 100</span></div>'
        if latest_score is not None
        else '<div class="hero-score score-empty"><strong>—</strong><span>NO SCAN</span></div>'
    )

    service_cards = []
    for service_id, service_name in service_items:
        service_cards.append(
            f'<details class="service-card" id="service-{service_id}">'
            f'<summary><span class="service-icon">{escape(service_name[:1])}</span>'
            f'<span>{escape(service_name)}</span><small>Open Red Team workspace</small></summary>'
            '<div class="service-info"><p>Dedicated service-specific Red Team workspace.</p>'
            f'<p class="muted"><a href="/admin/phishing-links/{escape(str(service_id))}">Open workspace</a></p></div></details>'
        )

    scan_section = f"""
        <div class="table-wrap"><table class="data-table">
            <thead><tr><th>ID</th><th>Hostname</th><th>Score</th><th>Grade</th>
            <th>Risk</th><th>Findings</th><th>Date</th><th>Report</th></tr></thead>
            <tbody>{scan_history}</tbody>
        </table></div>
    """

    strategy_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for scan in all_security_scans:
        risk = str(scan["risk_level"] or "info").lower()
        if risk not in strategy_counts:
            risk = "info"
        strategy_counts[risk] += 1

    max_strategy = max(strategy_counts.values(), default=0) or 1
    strategy_activity_rows = "".join(
        f'<div class="activity-row"><strong>{name.title()}</strong>'
        f'<div class="activity-track"><i style="width:{count / max_strategy * 100:.1f}%"></i></div>'
        f'<span>{count} scans</span></div>'
        for name, count in strategy_counts.items()
    )
    strategy_activity_html = (
        '<div class="panel strategy-panel"><h3>Strategy Activity</h3>'
        '<p class="muted">Recorded scans grouped by risk level</p>'
        + strategy_activity_rows + '</div>'
    )

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>PhishGuard Pro | Security Operations</title>
      <style>
        * {{ box-sizing:border-box; }}
        :root {{ --navy:#101c36; --blue:#315efb; --ink:#17233d; --muted:#71809a; --line:#e6ebf3; --bg:#f4f7fc; }}
        html {{ scroll-behavior:smooth; scroll-padding-top:24px; }}
        body {{ margin:0; background:var(--bg); color:var(--ink); font-family:Inter,Arial,sans-serif; }}
        .sidebar {{ position:fixed; inset:0 auto 0 0; width:252px; background:var(--navy); color:#fff; padding:26px 16px; overflow-y:auto; }}
        .brand {{ display:flex; align-items:center; gap:12px; padding:0 10px 28px; border-bottom:1px solid #293652; }}
        .brand-mark {{ width:40px; height:40px; display:grid; place-items:center; border-radius:12px; background:#315efb; font-weight:900; font-size:20px; }}
        .brand strong {{ display:block; font-size:16px; letter-spacing:.2px; }}
        .brand small {{ color:#9eacc5; font-size:10px; letter-spacing:1.2px; }}
        .nav-label {{ margin:25px 10px 10px; color:#8291ac; font-size:10px; font-weight:800; letter-spacing:1.5px; }}
        .nav-link {{ display:flex; align-items:center; gap:12px; padding:12px 13px; margin:4px 0; border-radius:9px; color:#c5cee0; text-decoration:none; font-size:13px; font-weight:600; }}
        .nav-link:hover,.nav-link.active {{ background:#24365c; color:#fff; }}
        .nav-link.active {{ box-shadow:inset 3px 0 #6d91ff; }}
        .nav-icon {{ width:20px; text-align:center; color:#91aaff; }}
        .sidebar-note {{ margin:30px 6px 0; padding:13px; border:1px solid #2c3c5b; border-radius:10px; color:#aebbd1; font-size:11px; line-height:1.6; }}
        .workspace {{ margin-left:252px; padding:30px 34px 60px; max-width:1600px; }}
        .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:27px; }}
        .eyebrow {{ color:var(--blue); font-size:10px; font-weight:800; letter-spacing:1.6px; }}
        h1 {{ margin:6px 0; font-size:27px; letter-spacing:-.7px; }}
        .subtitle,.muted {{ color:var(--muted); font-size:13px; }}
        .logout button,.primary-btn {{ border:0; border-radius:9px; padding:11px 16px; background:var(--blue); color:white; font-weight:700; cursor:pointer; }}
        .logout button {{ background:#fff; color:#33415d; border:1px solid var(--line); }}
        .notice {{ padding:13px 16px; background:#e8f7ef; color:#167344; border:1px solid #c8ecd8; border-radius:10px; margin-bottom:20px; }}
        .page-section {{ margin-bottom:30px; }}
        .section-head {{ display:flex; align-items:end; justify-content:space-between; gap:14px; margin:0 0 16px; }}
        .section-head h2 {{ margin:0 0 5px; font-size:19px; }}
        .section-head p {{ margin:0; color:var(--muted); font-size:12px; }}
        .panel,.stat-card,.welcome-card {{ background:#fff; border:1px solid var(--line); border-radius:15px; box-shadow:0 5px 20px rgba(23,35,61,.035); }}
        .welcome-card {{ padding:24px; display:grid; grid-template-columns:1fr auto; align-items:center; gap:20px; background:linear-gradient(115deg,#fff 55%,#eef3ff); }}
        .welcome-card h2 {{ margin:8px 0; font-size:21px; }}
        .welcome-card p {{ color:var(--muted); font-size:13px; line-height:1.6; }}
        .hero-score {{ width:126px; height:126px; border:9px solid currentColor; border-radius:50%; display:flex; flex-direction:column; align-items:center; justify-content:center; flex-shrink:0; }}
        .hero-score strong {{ font-size:37px; line-height:1; }}
        .hero-score span {{ font-size:9px; font-weight:800; margin-top:7px; letter-spacing:1px; }}
        .score-good {{ color:#15945c; background:#edfbf4; }}
        .score-warning {{ color:#d97706; background:#fff8e9; }}
        .score-risk {{ color:#dc4545; background:#fff0f0; }}
        .score-empty {{ color:#8491a7; background:#f3f5f8; }}
        .stats-grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:15px; margin:17px 0; }}
        .stat-card {{ padding:19px; }}
        .stat-card span {{ display:block; color:var(--muted); font-size:12px; font-weight:700; }}
        .stat-card strong {{ display:block; margin-top:9px; font-size:29px; }}
        .stat-card small {{ display:block; color:#9aa5b7; margin-top:5px; font-size:11px; }}
        .chart-grid {{ display:grid; grid-template-columns:1.2fr 1fr; gap:16px; }}
        .strategy-panel {{ margin-top:16px; }}
        .activity-row {{ display:grid; grid-template-columns:90px 1fr 75px; gap:12px; align-items:center; margin:14px 0; font-size:13px; }}
        .activity-track {{ height:9px; background:#edf1f7; border-radius:20px; overflow:hidden; }}
        .activity-track i {{ display:block; height:100%; background:#315efb; border-radius:20px; }}

        .panel {{ padding:21px; min-width:0; }}
        .panel h3 {{ margin:0 0 7px; font-size:15px; }}
        .bar-row {{ display:grid; grid-template-columns:80px 1fr 25px; align-items:center; gap:10px; margin:15px 0; font-size:11px; color:#65738b; }}
        .bar-track {{ height:9px; border-radius:20px; background:#edf1f7; overflow:hidden; }}
        .bar-track i {{ display:block; height:100%; border-radius:20px; }}
        .bar-critical {{ background:#b42336; }} .bar-high {{ background:#ed5555; }}
        .bar-medium {{ background:#f59e0b; }} .bar-low {{ background:#20a36a; }} .bar-info {{ background:#7c8ca8; }}
        .quick-links {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; margin-top:12px; }}
        .quick-links a {{ padding:13px; border:1px solid var(--line); border-radius:9px; color:#3154b8; text-decoration:none; font-size:12px; font-weight:700; }}
        .form-panel {{ max-width:760px; }}
        .form-panel label {{ display:block; margin:15px 0 7px; font-size:12px; font-weight:700; }}
        .form-panel input[type=url] {{ width:100%; padding:13px; border:1px solid #d5deeb; border-radius:9px; font-size:14px; }}
        .checkline {{ display:flex; align-items:center; gap:9px; margin:14px 0; color:#596981; font-size:12px; }}
        .info-grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:13px; }}
        .info-tile {{ padding:17px; border:1px solid var(--line); border-radius:11px; background:#fff; }}
        .info-tile strong {{ display:block; font-size:13px; margin-bottom:7px; }}
        .info-tile p {{ margin:0; color:var(--muted); font-size:12px; line-height:1.6; }}
        .service-grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:11px; }}
        .service-card {{ background:#fff; border:1px solid var(--line); border-radius:11px; overflow:hidden; }}
        .service-card summary {{ display:flex; align-items:center; gap:10px; padding:13px; cursor:pointer; list-style:none; font-size:12px; font-weight:700; }}
        .service-card summary::-webkit-details-marker {{ display:none; }}
        .service-card summary small {{ margin-left:auto; color:#9a6a24; font-size:9px; font-weight:700; }}
        .service-icon {{ width:31px; height:31px; display:grid; place-items:center; border-radius:9px; background:#edf2ff; color:#315efb; }}
        .service-info {{ border-top:1px solid var(--line); padding:12px; font-size:11px; line-height:1.6; }}
        .service-info p {{ margin:3px 0 8px; }}
        .table-wrap {{ overflow-x:auto; }}
        .data-table {{ width:100%; border-collapse:collapse; font-size:12px; min-width:760px; }}
        .data-table th {{ text-align:left; padding:13px 11px; background:#f5f7fb; color:#61708a; font-size:10px; text-transform:uppercase; letter-spacing:.5px; }}
        .data-table td {{ padding:13px 11px; border-bottom:1px solid #edf0f5; color:#42516a; }}
        .data-table a {{ color:#315efb; font-weight:700; text-decoration:none; }}
        .score-circle {{ display:inline-grid; place-items:center; width:42px; height:42px; border:3px solid currentColor; border-radius:50%; font-weight:800; }}
        .severity {{ display:inline-block; padding:5px 8px; border-radius:20px; font-size:10px; font-weight:800; }}
        .severity-critical,.severity-high {{ color:#a32332; background:#ffe5e7; }}
        .severity-medium {{ color:#9a5700; background:#fff0d5; }}
        .severity-low {{ color:#167344; background:#dcf8e9; }}
        .severity-info {{ color:#52627a; background:#e9eef5; }}
        .empty-state {{ padding:24px; color:var(--muted); text-align:center; font-size:13px; }}
        @media(max-width:1050px) {{ .sidebar {{ width:215px; }} .workspace {{ margin-left:215px; padding:24px; }} .service-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} }}
        @media(max-width:760px) {{ .sidebar {{ position:static; width:auto; padding:15px; }} .brand {{ padding-bottom:13px; }} .nav-label {{ margin-top:14px; }} .sidebar nav {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); }} .nav-link {{ margin:2px; padding:10px; }} .sidebar-note {{ display:none; }} .workspace {{ margin:0; padding:18px 14px 40px; }} .stats-grid,.chart-grid,.info-grid {{ grid-template-columns:1fr; }} .welcome-card {{ grid-template-columns:1fr auto; padding:17px; }} .hero-score {{ width:96px; height:96px; border-width:7px; }} .hero-score strong {{ font-size:29px; }} .service-grid {{ grid-template-columns:1fr; }} .topbar {{ align-items:flex-start; }} h1 {{ font-size:22px; }} }}
        @media print {{ .sidebar,.logout,.no-print {{ display:none !important; }} .workspace {{ margin:0; padding:0; }} body {{ background:#fff; }} .panel,.stat-card,.welcome-card {{ box-shadow:none; break-inside:avoid; }} }}

        .sidebar {{ transition: transform .25s ease; }}
        .workspace {{ transition: margin-left .25s ease; }}
        .sidebar-toggle {{
            border:1px solid #dce3ef;
            background:#fff;
            color:#17233d;
            border-radius:9px;
            padding:9px 13px;
            cursor:pointer;
            font-size:18px;
            margin-right:12px;
        }}
        body.sidebar-hidden .sidebar {{
            transform:translateX(-110%);
        }}
        body.sidebar-hidden .workspace {{
            margin-left:0;
        }}
</style>
    </head>
    <body>
      <aside class="sidebar">
        <div class="brand"><div class="brand-mark">P</div><div><strong>PhishGuard Pro</strong><small>SECURITY OPERATIONS</small></div></div>
        <div class="nav-label">WORKSPACE</div>
        <nav>
          <a class="nav-link active" href="/admin/dashboard"><span class="nav-icon">◈</span><span>Dashboard</span></a>
          <a class="nav-link" href="/admin/new-scan"><span class="nav-icon">⌕</span><span>New Scan</span></a>
          <a class="nav-link" href="/admin/full-scan"><span class="nav-icon">▦</span><span>Full Scan</span></a>
          <a class="nav-link" href="/admin/phishing-links"><span class="nav-icon">◇</span><span>Phishing Links</span></a>
          <a class="nav-link" href="/admin/link-generator"><span class="nav-icon">↗</span><span>Link Generator</span></a>
          <a class="nav-link" href="/admin/web-importer"><span class="nav-icon">▧</span><span>Web Importer</span></a>
          <a class="nav-link" href="/admin/security-tools"><span class="nav-icon">⚙</span><span>Security Tools</span></a>
          <a class="nav-link" href="/admin/email-validator"><span class="nav-icon">✉</span><span>Email Validator</span></a>
          <a class="nav-link" href="/admin/scan-reports"><span class="nav-icon">▤</span><span>Scan Reports</span></a>
        </nav>
        <div class="sidebar-note">Authorized security testing only. Scan systems you own or have explicit permission to assess.</div>
      </aside>
      <main class="workspace">
        <div class="topbar">
          <button type="button" class="sidebar-toggle no-print"
            onclick="document.body.classList.toggle('sidebar-hidden')"
            aria-label="Toggle sidebar" title="Open or close sidebar">☰</button>
          {period_filter_html}
          <div><div class="eyebrow">SECURITY CONTROL CENTER</div><h1>Dashboard Overview</h1><div class="subtitle">Monitor website security assessments and lab workspaces.</div></div>
          <form class="logout no-print" method="post" action="/admin/logout"><button type="submit">Log out</button></form>
        </div>
        {f'<p class="notice">{escape(message)}</p>' if message else ''}
        <section class="page-section" id="dashboard">
          <div class="welcome-card">
            <div><div class="eyebrow">LATEST SECURITY ASSESSMENT</div><h2>{latest_host}</h2>
            <p>Latest recorded security score. Review scan history for detailed findings and remediation guidance.</p>
            <a class="primary-btn" href="/admin/scan-reports" style="display:inline-block;text-decoration:none">View scan reports</a></div>
            {score_html}
          </div>
          <div class="stats-grid">
            <article class="stat-card"><span>Total scans shown</span><strong>{len(security_scans)}</strong><small>Latest 20 database records</small></article>
            <article class="stat-card"><span>Average security score</span><strong>{average_score if scores else "—"}</strong><small>Across displayed scans</small></article>
            <article class="stat-card"><span>Total findings</span><strong>{total_findings}</strong><small>Across displayed scan records</small></article>
          </div>
          <div class="chart-grid">
            <div class="panel"><h3>Findings by severity</h3><p class="muted">Severity counts from the latest 20 scans</p>{severity_bars}</div>

          </div>
          {strategy_activity_html}
          <div class="panel strategy-panel">
            <h3>Saved Scan Results</h3>
            <p class="muted">Previously recorded security scans</p>
            {scan_section}
          </div>
        </section>

      </main>
    </body>
    </html>
    """

    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "no-store"},
    )
from phishguard.email_validation import router as email_validator_router
router.include_router(email_validator_router)


@router.get(
    "/admin/link-generator",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_link_generator():
    with get_connection() as connection:
        links = connection.execute(
            """
            SELECT
                l.id,
                l.name,
                l.tracking_id,
                l.destination_url,
                l.status,
                l.created_at,
                COUNT(e.id) AS total_clicks,
                SUM(CASE WHEN e.source = 'direct' THEN 1 ELSE 0 END)
                    AS direct_clicks,
                SUM(CASE WHEN e.source = 'qr' THEN 1 ELSE 0 END)
                    AS qr_clicks
            FROM generated_links AS l
            LEFT JOIN generated_link_events AS e
                ON e.generated_link_id = l.id
            GROUP BY l.id
            ORDER BY l.id DESC
            LIMIT 200
            """
        ).fetchall()

        summary = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM generated_links) AS total_links,
                (SELECT COUNT(*) FROM generated_links WHERE status = 'active') AS active_links,
                (SELECT COUNT(*) FROM generated_links WHERE status = 'paused') AS paused_links,
                (SELECT COUNT(*) FROM generated_link_events) AS total_events,
                (SELECT COUNT(*) FROM generated_link_events WHERE source = 'direct') AS direct_events,
                (SELECT COUNT(*) FROM generated_link_events WHERE source = 'qr') AS qr_events
            """
        ).fetchone()

    rows = []
    for link in links:
        rows.append(
            "<tr>"
            f"<td>{escape(str(link['name']))}</td>"
            f"<td><code>{escape(str(link['tracking_id']))}</code></td>"
            f"<td>{escape(str(link['status']))}</td>"
            f"<td><form method='post' action='/admin/link-generator/{escape(str(link['tracking_id']))}/status'>"
            f"<input type='hidden' name='status' value='{'paused' if link['status'] == 'active' else 'active'}'>"
            f"<button type='submit'>{'Pause' if link['status'] == 'active' else 'Resume'}</button></form></td>"
            f"<td>{link['total_clicks'] or 0}</td>"
            f"<td>{link['direct_clicks'] or 0}</td>"
            f"<td>{link['qr_clicks'] or 0}</td>"
            f"<td><a href='/admin/link-generator/{escape(str(link['tracking_id']))}/qr'>Download QR</a></td>"
            f"<td><a href='/admin/link-generator/{escape(str(link['tracking_id']))}/history'>View History</a></td>"
            f"<td><code>{escape(LOCAL_PREVIEW_BASE_URL.rstrip('/') + '/r/' + str(link['tracking_id']))}</code></td>"
            f"<td>{escape(str(link['created_at']))}</td>"
            "</tr>"
        )

    if not rows:
        rows.append(
            '<tr><td colspan="11">No generated links yet.</td></tr>'
        )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link Generator | PhishGuard Pro</title>
<style>
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 32px; background: #f5f7fb;
       color: #17233d; font-family: Arial, sans-serif; }}
main {{ max-width: 1150px; margin: auto; }}
header {{ display: flex; justify-content: space-between;
          align-items: center; gap: 16px; margin-bottom: 28px; }}
h1 {{ margin: 0 0 8px; font-size: 27px; }}
.subtitle, .muted {{ color: #64748b; }}
.back {{ color: #2457c5; text-decoration: none; font-weight: 600; }}
.panel {{ background: white; border: 1px solid #e2e8f0;
          border-radius: 12px; padding: 22px; margin-bottom: 22px; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; margin-bottom: 22px; }}
.summary-card {{ background: white; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; }}
.summary-card strong {{ display: block; font-size: 25px; margin-top: 8px; }}
input[type=text], input[type=url] {{
    width: 100%; padding: 12px; margin: 8px 0 16px;
    border: 1px solid #cbd5e1; border-radius: 7px;
}}
button {{ background: #2457c5; color: white; border: 0;
          padding: 12px 20px; border-radius: 7px; cursor: pointer; }}
table {{ width: 100%; border-collapse: collapse; background: white; }}
th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; }}
th {{ background: #f8fafc; }}
.table-wrap {{ overflow-x: auto; }}
code {{ overflow-wrap: anywhere; }}
.notice {{ color: #475569; background: #f1f5f9;
           padding: 12px; border-radius: 8px; }}
</style>
</head>
<body>
<main>
<header>
<div><h1>Link Generator</h1>
<div class="subtitle">Create and monitor links for authorized destinations.</div></div>
<a class="back" href="/admin/dashboard">Back to Dashboard</a>
</header>

<section class="summary-grid">
<div class="summary-card">Total Links<strong>{summary['total_links'] or 0}</strong></div>
<div class="summary-card">Active Links<strong>{summary['active_links'] or 0}</strong></div>
<div class="summary-card">Paused Links<strong>{summary['paused_links'] or 0}</strong></div>
<div class="summary-card">Total Events<strong>{summary['total_events'] or 0}</strong></div>
<div class="summary-card">Direct Events<strong>{summary['direct_events'] or 0}</strong></div>
<div class="summary-card">QR Events<strong>{summary['qr_events'] or 0}</strong></div>
</section>

<section class="panel">
<h2>Create a tracking link</h2>
<p class="muted">Only use websites you own or are explicitly authorized to track.</p>
<form method="post" action="/admin/link-generator/create">
<label for="name">Link name</label>
<input id="name" name="name" type="text" maxlength="100"
       placeholder="Campaign or project name" required>
<label for="destination_url">Authorized HTTPS destination</label>
<input id="destination_url" name="destination_url" type="url"
       maxlength="2048" placeholder="https://your-authorized-domain.example/page"
       required>
<label for="service_slug">Security review workspace (optional)</label>
<select id="service_slug" name="service_slug">
<option value="">General tracking link</option>
<option value="facebook">Facebook</option>
<option value="instagram">Instagram</option>
<option value="tiktok">TikTok</option>
<option value="snapchat">Snapchat</option>
<option value="paypal">PayPal</option>
<option value="google">Google</option>
<option value="microsoft">Microsoft</option>
<option value="netflix">Netflix</option>
<option value="linkedin">LinkedIn</option>
<option value="x">X</option>
<option value="amazon">Amazon</option>
<option value="apple">Apple</option>
<option value="discord">Discord</option>
<option value="telegram">Telegram</option>
<option value="steam">Steam</option>
<option value="spotify">Spotify</option>
<option value="yahoo">Yahoo</option>
<option value="reddit">Reddit</option>
<option value="pinterest">Pinterest</option>
<option value="twitch">Twitch</option>
<option value="zoom">Zoom</option>
<option value="dropbox">Dropbox</option>
<option value="github">GitHub</option>
</select>
<label for="count">Number of links (1–100)</label>
<input id="count" name="count" type="number" min="1" max="100"
       value="1" required>
<label><input type="checkbox" name="authorized" value="yes" required>
I confirm I own this destination or have permission to use it.</label>
<p><button type="submit">Create tracking link</button></p>
</form>
</section>

<section class="panel">
<h2>Generated links</h2>
<p class="muted">Showing up to 200 newest links. Click totals are separated by source.</p>
<div class="table-wrap">
<table>
<thead><tr>
<th>Name</th><th>Tracking ID</th><th>Status</th><th>Action</th>
<th>Total clicks</th><th>Direct</th><th>QR</th><th>QR Code</th><th>History</th><th>Tracking URL</th><th>Created</th>
</tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</div>
</section>
<p class="notice">IP address and device information are not collected unless the visitor explicitly consents. Tracking URLs and QR codes are available for authorized destinations.</p>
</main>
</body>
</html>"""

    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


@router.get(
    "/admin/link-generator/analytics",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_generated_link_analytics(
    start_date: str = "",
    end_date: str = "",
):
    today = dt.date.today().isoformat()
    start_date = start_date or today
    end_date = end_date or today

    try:
        report = get_generated_link_analytics(start_date, end_date)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    rows = "".join(
        "<tr>"
        f"<td>{escape(str(day['event_date']))}</td>"
        f"<td>{day['total_events']}</td>"
        f"<td>{day['direct_events']}</td>"
        f"<td>{day['qr_events']}</td>"
        "</tr>"
        for day in report["daily"]
    ) or '<tr><td colspan="4">No events in this date range.</td></tr>'

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link Analytics | PhishGuard Pro</title>
<style>
body {{ margin:0; padding:30px; background:#f5f7fb; color:#17233d; font-family:Arial,sans-serif; }}
main {{ max-width:1000px; margin:auto; }}
.panel {{ background:white; border:1px solid #e2e8f0; border-radius:10px; padding:20px; margin:18px 0; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }}
.card {{ background:white; border:1px solid #e2e8f0; border-radius:9px; padding:18px; }}
.card strong {{ display:block; font-size:25px; margin-top:8px; }}
input,button {{ padding:10px; margin:6px; }}
button {{ background:#2457c5; color:white; border:0; border-radius:6px; cursor:pointer; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ padding:12px; text-align:left; border-bottom:1px solid #e2e8f0; }}
th {{ background:#f8fafc; }}
</style>
</head>
<body><main>
<h1>Generated Link Analytics</h1>
<p><a href="/admin/link-generator">Back to Link Generator</a></p>
<section class="panel">
<form method="get">
<label>From <input type="date" name="start_date" value="{escape(start_date)}" required></label>
<label>To <input type="date" name="end_date" value="{escape(end_date)}" required></label>
<button type="submit">Apply Date Range</button>
</form>
</section>
<section class="cards">
<div class="card">Total Events<strong>{report['total_events']}</strong></div>
<div class="card">Direct Events<strong>{report['direct_events']}</strong></div>
<div class="card">QR Events<strong>{report['qr_events']}</strong></div>
</section>
<section class="panel">
<h2>Daily Breakdown</h2>
<table><thead><tr><th>Date</th><th>Total</th><th>Direct</th><th>QR</th></tr></thead>
<tbody>{rows}</tbody></table>
</section>
</main></body></html>"""
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


@router.post(
    "/admin/link-generator/create",
    dependencies=[Depends(verify_admin_session), Depends(verify_admin_origin)],
)
def admin_create_generated_link(
    name: str = Form(..., max_length=100),
    destination_url: str = Form(..., max_length=2048),
    authorized: str = Form(...),
    count: int = Form(1),
    service_slug: str = Form(""),
):
    if authorized != "yes":
        raise HTTPException(
            status_code=400,
            detail="Authorization confirmation is required.",
        )

    try:
        selected_service = service_slug.strip() or None
        if count == 1:
            if selected_service is None:
                create_generated_link(name, destination_url)
            else:
                create_generated_link(name, destination_url, selected_service)
        else:
            if selected_service is None:
                create_generated_links(name, destination_url, count)
            else:
                create_generated_links(name, destination_url, count, selected_service)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return RedirectResponse(
        url="/admin/link-generator",
        status_code=303,
    )



@router.get(
    "/admin/link-generator/{tracking_id}/history",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_admin_session)],
)
def admin_generated_link_history(tracking_id: str, offset: int = 0):
    try:
        history = get_generated_link_history(tracking_id, limit=50, offset=offset)
    except ValueError as error:
        status_code = 404 if "not found" in str(error).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(error)) from error

    rows = []
    for event in history["events"]:
        details = []
        if event["consent_ip"]:
            if event["ip_address"]:
                details.append("IP: " + escape(str(event["ip_address"])))
            if event["country_code"]:
                details.append("Country: " + escape(str(event["country_code"])))
        if event["consent_device"]:
            for label, key in (
                ("Browser", "browser_name"),
                ("OS", "os_name"),
                ("Device", "device_type"),
                ("User-Agent", "user_agent"),
            ):
                if event[key]:
                    details.append(label + ": " + escape(str(event[key])))

        rows.append(
            "<tr>"
            f"<td>{escape(str(event['created_at']))}</td>"
            f"<td>{escape(str(event['source']))}</td>"
            f"<td>{'<br>'.join(details) if details else 'Not collected'}</td>"
            "</tr>"
        )

    if not rows:
        rows.append('<tr><td colspan="3">No events recorded.</td></tr>')

    total = history["total_events"]
    previous = (
        f'<a href="?offset={max(0, offset - 50)}">Previous</a>'
        if offset > 0 else ""
    )
    next_page = (
        f'<a href="?offset={offset + 50}">Next</a>'
        if offset + 50 < total else ""
    )

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link History | PhishGuard Pro</title>
<style>
body {{ margin:0; padding:32px; background:#f5f7fb; color:#17233d;
font-family:Arial,sans-serif; }}
main {{ max-width:1100px; margin:auto; }}
.panel {{ background:white; padding:22px; border:1px solid #e2e8f0;
border-radius:12px; overflow-x:auto; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; padding:12px; border-bottom:1px solid #e2e8f0;
vertical-align:top; overflow-wrap:anywhere; }}
th {{ background:#f8fafc; }}
a {{ color:#2457c5; }}
nav {{ display:flex; gap:20px; margin-top:20px; }}
</style></head><body><main>
<h1>Generated Link History</h1>
<p>Tracking ID: <code>{escape(tracking_id)}</code></p>
<section class="panel">
<p>Total events: {total}</p>
<table><thead><tr><th>Time</th><th>Source</th><th>Consented details</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<nav>{previous}{next_page}</nav>
</section>
<p><a href="/admin/link-generator">Back to Link Generator</a></p>
</main></body></html>"""
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


@router.post(
    "/admin/link-generator/{tracking_id}/status",
    dependencies=[Depends(verify_admin_session), Depends(verify_admin_origin)],
)
def admin_update_generated_link_status(
    tracking_id: str,
    status: str = Form(...),
):
    try:
        set_generated_link_status(tracking_id, status)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return RedirectResponse(
        url="/admin/link-generator",
        status_code=303,
    )


@router.get(
    "/admin/link-generator/{tracking_id}/qr",
    dependencies=[Depends(verify_admin_session)],
)
def admin_download_generated_link_qr(tracking_id: str):
    try:
        link = resolve_generated_link(tracking_id)
        tracking_url = (
            LOCAL_PREVIEW_BASE_URL.rstrip("/") + "/r/" + tracking_id
        )
        qr_path = generate_qr_code(tracking_url, tracking_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="Link unavailable.") from error

    return FileResponse(
        qr_path,
        media_type="image/png",
        filename=f"{tracking_id}.png",
        headers={"Cache-Control": "no-store"},
    )
