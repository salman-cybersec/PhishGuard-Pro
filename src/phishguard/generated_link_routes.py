import ipaddress

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from phishguard.device_info import parse_device_info
from phishguard.link_generator import (
    resolve_generated_link,
    record_generated_link_event,
)
from phishguard.website_authorization import validate_website_authorization
from phishguard.service_workspaces import (
    SERVICE_DISPLAY_NAMES,
    SERVICE_WORKSPACES,
    render_service_workspace,
)

router = APIRouter()


@router.get("/r/{tracking_id}", response_class=HTMLResponse)
def open_generated_link(
    tracking_id: str,
    source: str = Query(default="direct"),
):
    if source not in {"direct", "qr"}:
        raise HTTPException(status_code=400, detail="Invalid source.")

    try:
        link = resolve_generated_link(tracking_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="Link unavailable.") from error

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Destination</title>
<style>
body{{font-family:Arial;background:#f4f6fa;color:#17233d;margin:0;padding:30px}}
main{{max-width:520px;margin:50px auto;background:white;padding:28px;border-radius:12px}}
.notice{{background:#eef4ff;padding:14px;border-left:4px solid #2457c5;line-height:1.5}}
label{{display:block;margin:16px 0;line-height:1.5}}
button{{background:#2457c5;color:white;border:0;padding:12px 20px;border-radius:7px}}
</style>
</head>
<body><main>
<h2>Authorized Security Assessment</h2>
<p class="notice">This link is part of an authorized security assessment.
No passwords, OTPs, or account credentials are requested or collected.
Optional data collection choices are listed below.</p>
<form method="post" action="/r/{tracking_id}/continue?source={source}">
<label><input type="checkbox" name="consent_ip" value="yes">
I consent to recording my public IP address.</label>
<label><input type="checkbox" name="consent_device" value="yes">
I consent to recording browser, operating system and device information.</label>
<button type="submit">{'Continue to security review workspace' if link.get("service_slug") else 'Continue to destination'}</button>
</form>
</main></body></html>"""

    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


@router.post("/r/{tracking_id}/continue")
def continue_generated_link(
    tracking_id: str,
    request: Request,
    source: str = Query(default="direct"),
    consent_ip: str | None = Form(default=None),
    consent_device: str | None = Form(default=None),
):
    if source not in {"direct", "qr"}:
        raise HTTPException(status_code=400, detail="Invalid source.")
    if consent_ip not in (None, "yes") or consent_device not in (None, "yes"):
        raise HTTPException(status_code=400, detail="Invalid consent choice.")

    try:
        link = resolve_generated_link(tracking_id)
        validate_website_authorization(link["destination_url"])

        collect_ip = consent_ip == "yes"
        collect_device = consent_device == "yes"
        client_ip = None
        user_agent = None
        device_info = {}

        if collect_ip and request.client:
            try:
                candidate = ipaddress.ip_address(request.client.host)
                if candidate.is_global:
                    client_ip = candidate.compressed
            except ValueError:
                pass

        if collect_device:
            user_agent = request.headers.get("user-agent", "")[:500] or None
            if user_agent:
                device_info = parse_device_info(user_agent)

        record_generated_link_event(
            tracking_id=tracking_id,
            source=source,
            consent_ip=collect_ip,
            ip_address=client_ip,
            consent_device=collect_device,
            user_agent=user_agent,
            browser_name=device_info.get("browser_name"),
            os_name=device_info.get("os_name"),
            device_type=device_info.get("device_type"),
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail="Link unavailable.") from error

    service_slug = link.get("service_slug")
    if service_slug:
        config = SERVICE_WORKSPACES.get(service_slug)
        service_name = SERVICE_DISPLAY_NAMES.get(service_slug)
        if config is None or service_name is None:
            raise HTTPException(status_code=404, detail="Workspace unavailable.")
        response = HTMLResponse(
            render_service_workspace(service_name, config)
        )
    else:
        response = RedirectResponse(
            url=link["destination_url"],
            status_code=303,
        )

    response.headers["Cache-Control"] = "no-store"
    return response
