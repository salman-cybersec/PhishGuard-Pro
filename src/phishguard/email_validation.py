import csv
import io
import re
from html import escape

import dns.exception
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

from phishguard.auth import verify_admin_session, verify_admin_origin

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
:root{{
 --bg:#f4f7fc;--surface:#fff;--ink:#17233d;--muted:#71809a;
 --blue:#315efb;--blue-dark:#244bd1;--line:#e6ebf3;
 --soft-blue:#edf3ff;--shadow:0 5px 22px rgba(25,45,85,.055)
}}
body{{margin:0;background:var(--bg);color:var(--ink);
 font:15px Inter,Arial,sans-serif;line-height:1.55}}
header{{background:#fff;color:var(--ink);padding:18px 30px;
 border-bottom:1px solid var(--line);box-shadow:0 2px 10px rgba(20,40,80,.035)}}
header strong{{font-size:20px;font-weight:750;letter-spacing:-.4px}}
header a{{color:var(--blue);text-decoration:none;float:right;font-weight:600}}
header a:hover{{text-decoration:underline}}
main{{max-width:1160px;margin:34px auto;padding:0 22px}}
h1{{font-size:28px;line-height:1.25;letter-spacing:-.7px;margin:0 0 8px}}
h2{{font-size:18px;letter-spacing:-.2px;margin:0 0 16px}}
p{{margin:8px 0}}
.muted{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}}
.card{{background:var(--surface);border:1px solid var(--line);
 border-radius:14px;padding:24px;margin:20px 0;box-shadow:var(--shadow)}}
textarea,input[type=email],input[type=file]{{
 width:100%;padding:12px 14px;border:1px solid #d6deea;
 border-radius:9px;margin:8px 0 15px;font:inherit;color:var(--ink);
 background:#fff;transition:border-color .15s,box-shadow .15s
}}
textarea{{min-height:140px;resize:vertical}}
textarea:focus,input:focus{{outline:none;border-color:var(--blue);
 box-shadow:0 0 0 3px rgba(49,94,251,.12)}}
button{{background:var(--blue);color:white;border:0;border-radius:9px;
 padding:11px 18px;font:inherit;font-weight:650;cursor:pointer;
 transition:background .15s,transform .15s}}
button:hover{{background:var(--blue-dark)}}
button:active{{transform:translateY(1px)}}
.notice{{background:var(--soft-blue);border:1px solid #d8e4ff;
 padding:13px 15px;border-radius:10px;color:#294d83;margin:16px 0}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}}
.stat{{padding:12px 16px;border:1px solid var(--line);
 border-radius:10px;background:#f8faff}}
.valid{{color:#087443}}.invalid{{color:#bd3030}}
.unknown{{color:#946200}}.duplicate{{color:#6251a5}}
table{{width:100%;border-collapse:collapse;margin-top:14px;background:#fff}}
th,td{{padding:12px 13px;text-align:left;border-bottom:1px solid var(--line);
 overflow-wrap:anywhere}}
th{{background:#f7f9fd;color:#52627c;font-size:13px;font-weight:700}}
.export{{display:inline-block;margin:8px 8px 0 0}}
@media(max-width:700px){{
 header{{padding:16px 18px}}
 header a{{float:none;display:block;margin-top:8px}}
 main{{margin:24px auto;padding:0 15px}}
 h1{{font-size:24px}}
 .grid{{grid-template-columns:1fr}}
 .card{{padding:18px}}
 table{{display:block;overflow-x:auto;white-space:nowrap}}
}}
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
def single_check(email: str = Form(...), admin=Depends(verify_admin_session), csrf=Depends(verify_admin_origin)):
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
    csrf=Depends(verify_admin_origin),
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
    csrf=Depends(verify_admin_origin),
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
