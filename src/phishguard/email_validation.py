import csv
import io
import re
from html import escape

import dns.exception
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

from phishguard.auth import verify_admin_session

router = APIRouter(prefix="/admin/email-validator", tags=["Email Validator"])

MAX_ENTRIES = 5000
MAX_UPLOAD_BYTES = 2 * 1024 * 1024


def check_email(value):
    value = value.strip()

    if not value:
        return {"email": value, "status": "Invalid", "reason": "Empty value"}

    try:
        parsed = validate_email(value, check_deliverability=False)
        normalized = parsed.normalized
    except EmailNotValidError as exc:
        return {"email": value, "status": "Invalid", "reason": str(exc)}

    domain = normalized.rsplit("@", 1)[1]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4

    try:
        resolver.resolve(domain, "MX")
        return {"email": normalized, "status": "Valid", "reason": "MX record found"}
    except dns.resolver.NXDOMAIN:
        return {"email": normalized, "status": "Invalid", "reason": "Domain does not exist"}
    except dns.resolver.NoAnswer:
        pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return {"email": normalized, "status": "Unknown", "reason": "DNS lookup timed out or failed"}

    for record_type in ("A", "AAAA"):
        try:
            resolver.resolve(domain, record_type)
            return {
                "email": normalized,
                "status": "Valid",
                "reason": "Domain address record found (fallback routing)"
            }
        except dns.resolver.NXDOMAIN:
            return {"email": normalized, "status": "Invalid", "reason": "Domain does not exist"}
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            return {"email": normalized, "status": "Unknown", "reason": "DNS lookup inconclusive"}

    return {"email": normalized, "status": "Invalid", "reason": "No MX or address record found"}


def page(content="", message=""):
    return HTMLResponse(f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Email Validator | PhishGuard Pro</title>
      <style>
        *{{box-sizing:border-box}}
        body{{margin:0;background:#f3f6fb;color:#17243a;font:15px Arial,sans-serif}}
        header{{background:#101d35;color:white;padding:22px 30px}}
        header strong{{font-size:20px}} header a{{color:#cbd8ed;text-decoration:none;float:right}}
        main{{max-width:1100px;margin:28px auto;padding:0 18px}}
        h1{{font-size:27px;margin:0 0 8px}} .muted{{color:#718096}}
        .grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
        .card{{background:white;border:1px solid #e2e8f0;border-radius:13px;padding:22px;margin:18px 0;box-shadow:0 4px 16px #15243a0a}}
        h2{{font-size:18px;margin:0 0 15px}}
        textarea,input[type=email],input[type=file]{{width:100%;padding:12px;border:1px solid #ccd5e1;border-radius:8px;margin:8px 0 14px;font:inherit}}
        textarea{{min-height:135px;resize:vertical}}
        button{{background:#2459c4;color:white;border:0;border-radius:8px;padding:11px 17px;font-weight:600;cursor:pointer}}
        button:hover{{background:#19469e}}
        .notice{{background:#edf4ff;border:1px solid #c9dcff;padding:12px;border-radius:8px;color:#294d83;margin:14px 0}}
        .stats{{display:flex;gap:10px;flex-wrap:wrap;margin:15px 0}}
        .stat{{padding:10px 14px;border-radius:8px;background:#f1f5f9}}
        .valid{{color:#087443}} .invalid{{color:#bd3030}} .unknown{{color:#946200}} .duplicate{{color:#6251a5}}
        table{{width:100%;border-collapse:collapse;margin-top:12px}}
        th,td{{padding:11px;text-align:left;border-bottom:1px solid #e7edf4;overflow-wrap:anywhere}}
        th{{background:#f6f8fb}} .export{{display:inline-block;margin:8px 8px 0 0}}
        @media(max-width:700px){{.grid{{grid-template-columns:1fr}}header a{{float:none;display:block;margin-top:10px}}}}
      </style>
    </head>
    <body>
      <header><strong>PhishGuard Pro</strong> — Email Validator
        <a href="/admin/dashboard">← Back to Dashboard</a>
      </header>
      <main>
        <h1>Email Validator</h1>
        <p class="muted">Check email syntax and domain mail-routing records.</p>
        <div class="notice">
          A Valid result means the address format is valid and its domain has mail-routing
          records. It does not confirm that the individual mailbox exists or accepts mail.
          No email is sent and no mailbox is probed.
        </div>
        <div class="grid">
          <section class="card">
            <h2>Single Email Check</h2>
            <form method="post" action="/admin/email-validator/check">
              <label for="email">Email address</label>
              <input id="email" type="email" name="email" placeholder="name@example.com" required>
              <button type="submit">Validate Email</button>
            </form>
          </section>
          <section class="card">
            <h2>Bulk Email Check</h2>
            <form method="post" action="/admin/email-validator/bulk" enctype="multipart/form-data">
              <label for="emails">Paste emails (one per line, or comma/semicolon separated)</label>
              <textarea id="emails" name="emails" placeholder="user1@example.com&#10;user2@example.com"></textarea>
              <label for="upload">Or upload TXT / CSV (max 2 MB)</label>
              <input id="upload" type="file" name="upload" accept=".txt,.csv,text/plain,text/csv">
              <button type="submit">Validate Bulk List</button>
            </form>
            <p class="muted">Maximum 5,000 entries. Repeated addresses are separated as duplicates.</p>
          </section>
        </div>
        {message}
        {content}
      </main>
    </body>
    </html>
    """)


@router.get("", response_class=HTMLResponse)
def email_validator_home(admin=Depends(verify_admin_session)):
    return page()


@router.post("/check", response_class=HTMLResponse)
def single_check(email: str = Form(...), admin=Depends(verify_admin_session)):
    result = check_email(email)
    status_class = result["status"].lower()
    content = f"""
    <section class="card">
      <h2>Single Email Result</h2>
      <p><strong>{escape(result['email'])}</strong></p>
      <p class="{status_class}"><strong>{escape(result['status'])}</strong></p>
      <p class="muted">{escape(result['reason'])}</p>
    </section>
    """
    return page(content)


@router.post("/bulk", response_class=HTMLResponse)
async def bulk_check(
    emails: str = Form(""),
    upload: UploadFile | None = File(None),
    admin=Depends(verify_admin_session),
):
    values = [emails] if emails.strip() else []

    if upload and upload.filename:
        filename = upload.filename.lower()
        if not (filename.endswith(".txt") or filename.endswith(".csv")):
            raise HTTPException(status_code=400, detail="Only TXT and CSV files are supported.")
        raw = await upload.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Upload exceeds the 2 MB limit.")
        try:
            values.append(raw.decode("utf-8-sig"))
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File must use UTF-8 text encoding.")

    combined = "\n".join(values)
    addresses = [item.strip().strip('"').strip("'") for item in re.split(r"[\s,;]+", combined) if item.strip()]

    if not addresses:
        return page(message='<div class="notice">Paste or upload at least one email address.</div>')

    if len(addresses) > MAX_ENTRIES:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_ENTRIES} entries are allowed.")

    seen = set()
    results = []
    for address in addresses:
        key = address.casefold()
        if key in seen:
            results.append({"email": address, "status": "Duplicate", "reason": "Repeated address"})
            continue
        seen.add(key)
        results.append(check_email(address))

    groups = {
        "Valid": [r["email"] for r in results if r["status"] == "Valid"],
        "Invalid": [r["email"] for r in results if r["status"] == "Invalid"],
        "Unknown": [r["email"] for r in results if r["status"] == "Unknown"],
        "Duplicate": [r["email"] for r in results if r["status"] == "Duplicate"],
    }

    stats = "".join(
        f'<div class="stat"><strong class="{name.lower()}">{name}: {len(items)}</strong></div>'
        for name, items in groups.items()
    )
    rows = "".join(
        f'<tr><td>{escape(r["email"])}</td><td class="{r["status"].lower()}"><strong>{escape(r["status"])}</strong></td><td>{escape(r["reason"])}</td></tr>'
        for r in results
    )
    exports = ""
    for name, items in groups.items():
        if items:
            joined = escape("\n".join(items), quote=True)
            exports += f"""
            <form class="export" method="post" action="/admin/email-validator/export">
              <input type="hidden" name="category" value="{name}">
              <textarea hidden name="addresses">{joined}</textarea>
              <button type="submit">Export {name} CSV</button>
            </form>
            """

    content = f"""
    <section class="card">
      <h2>Bulk Validation Results</h2>
      <div class="stats">{stats}</div>
      <p class="muted">Processed {len(results)} entries. Duplicate entries are not re-validated.</p>
      {exports}
      <table>
        <thead><tr><th>Email</th><th>Status</th><th>Details</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    """
    return page(content)


@router.post("/export")
def export_csv(
    category: str = Form(...),
    addresses: str = Form(...),
    admin=Depends(verify_admin_session),
):
    if category not in {"Valid", "Invalid", "Unknown", "Duplicate"}:
        raise HTTPException(status_code=400, detail="Invalid export category.")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Email", "Category"])
    for address in addresses.splitlines():
        if address.strip():
            writer.writerow([address.strip(), category])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{category.lower()}-emails.csv"'},
    )
