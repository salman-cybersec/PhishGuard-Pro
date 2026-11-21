import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from phishguard.safe_http import (
    REQUEST_TIMEOUT,
    resolve_public_addresses,
    fetch_https,
)

from phishguard.security_score import calculate_security_score
from phishguard.technology_detector import detect_technologies


MAX_RESPONSE_BYTES = 65536

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def validate_target_url(url: str) -> tuple:
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Invalid URL.")

    parsed = urlsplit(url.strip())

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise ValueError("Only valid HTTPS URLs on port 443 are accepted.")

    hostname = parsed.hostname.lower().rstrip(".")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("IP-literal targets are not accepted.")

    if (
        not hostname
        or hostname == "localhost"
        or "." not in hostname
        or any(char.isspace() for char in hostname)
    ):
        raise ValueError("Invalid public hostname.")

    return parsed, hostname


def inspect_tls(hostname: str, addresses: list) -> dict:
    context = ssl.create_default_context()
    last_error = None

    for address in addresses:
        connection = None

        try:
            raw_socket = socket.create_connection(
                (address, 443),
                timeout=REQUEST_TIMEOUT,
            )

            try:
                connection = context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                )
            except Exception:
                raw_socket.close()
                raise

            certificate = connection.getpeercert()

            not_after = certificate.get("notAfter")

            expiry = None
            days_remaining = None

            if not_after:
                expiry_date = datetime.strptime(
                    not_after,
                    "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)

                days_remaining = (
                    expiry_date - datetime.now(timezone.utc)
                ).days

                expiry = expiry_date.isoformat()

            return {
                "valid": True,
                "version": connection.version(),
                "expires_at": expiry,
                "days_remaining": days_remaining,
            }

        except (OSError, ssl.SSLError, ValueError) as error:
            last_error = error

        finally:
            if connection is not None:
                connection.close()

    raise RuntimeError(
        "TLS certificate inspection failed."
    ) from last_error


def analyze_security_headers(headers) -> dict:
    findings = []
    present = []

    normalized = {
        key.lower(): value
        for key, value in headers.items()
    }

    for header, label in SECURITY_HEADERS.items():
        if header in normalized:
            present.append(label)
        else:
            findings.append({
                "severity": "medium",
                "finding": f"Missing {label} header",
            })

    return {
        "present": present,
        "missing": [
            item["finding"].replace("Missing ", "").replace(" header", "")
            for item in findings
        ],
        "findings": findings,
    }



def analyze_cookie_security(headers) -> dict:
    """Inspect cookie security attributes without storing cookie values."""
    from http.cookies import SimpleCookie

    raw_values = []

    if hasattr(headers, "get_all"):
        raw_values = headers.get_all("Set-Cookie", []) or []
    else:
        for key, value in headers.items():
            if str(key).lower() == "set-cookie":
                raw_values = value if isinstance(value, list) else [value]
                break

    cookies = []
    findings = []

    for raw in raw_values:
        parsed = SimpleCookie()

        try:
            parsed.load(str(raw))
        except Exception:
            continue

        for name, morsel in parsed.items():
            flags = {
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": bool(morsel["samesite"]),
            }

            cookies.append({"name": name, **flags})

            if not flags["secure"]:
                findings.append({
                    "severity": "medium",
                    "finding": f"Cookie {name} is missing the Secure flag",
                })

            if not flags["httponly"]:
                findings.append({
                    "severity": "medium",
                    "finding": f"Cookie {name} is missing the HttpOnly flag",
                })

            if not flags["samesite"]:
                findings.append({
                    "severity": "low",
                    "finding": f"Cookie {name} is missing the SameSite attribute",
                })

    return {
        "cookies": cookies,
        "count": len(cookies),
        "findings": findings,
    }


def analyze_website(url: str, *, include_page_content: bool = False) -> dict:
    parsed, hostname = validate_target_url(url)

    addresses = resolve_public_addresses(hostname)

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Non-public IP address blocked.")

    tls = inspect_tls(hostname, addresses)

    response = fetch_https(
        url=url.strip(),
        expected_host=hostname,
        max_bytes=MAX_RESPONSE_BYTES,
    )

    if 300 <= response["status_code"] < 400:
        raise RuntimeError(
            "Website returned a redirect. Redirects are not followed."
        )

    if response["status_code"] >= 400:
        raise RuntimeError(
            f"Website returned HTTP {response['status_code']}."
        )

    technology_analysis = detect_technologies(
        response["headers"],
        response["content"],
    )

    header_analysis = analyze_security_headers(
        response["headers"]
    )

    findings = list(header_analysis["findings"])

    if tls["days_remaining"] is not None:
        if tls["days_remaining"] < 0:
            findings.append({
                "severity": "high",
                "finding": "TLS certificate has expired",
            })
        elif tls["days_remaining"] <= 30:
            findings.append({
                "severity": "medium",
                "finding": "TLS certificate expires within 30 days",
            })


    remediation_advice = {
        "Missing HSTS header": (
            "Configure Strict-Transport-Security with an appropriate "
            "max-age. Enable includeSubDomains only when all subdomains "
            "support HTTPS."
        ),
        "Missing CSP header": (
            "Deploy a Content-Security-Policy based on the website's "
            "actual resource requirements. Start with report-only mode."
        ),
        "Missing X-Content-Type-Options header": (
            "Set X-Content-Type-Options: nosniff."
        ),
        "Missing X-Frame-Options header": (
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use "
            "frame-ancestors in Content-Security-Policy."
        ),
        "Missing Referrer-Policy header": (
            "Configure a suitable Referrer-Policy, such as "
            "strict-origin-when-cross-origin."
        ),
        "Missing Permissions-Policy header": (
            "Restrict browser features such as camera, microphone, "
            "and geolocation when they are not required."
        ),
        "TLS certificate has expired": (
            "Renew and deploy a valid TLS certificate immediately."
        ),
        "TLS certificate expires within 30 days": (
            "Renew the TLS certificate before its expiry date."
        ),
    }

    for item in findings:
        item["remediation"] = remediation_advice.get(
            item["finding"],
            "Review this finding and apply an appropriate security fix.",
        )


    security_score = calculate_security_score(findings)

    high = sum(
        item["severity"] == "high"
        for item in findings
    )

    medium = sum(
        item["severity"] == "medium"
        for item in findings
    )

    risk = (
        "high" if high else
        "medium" if medium else
        "low"
    )

    return {
        "hostname": hostname,
        "url": f"{parsed.scheme}://{hostname}{parsed.path or '/'}",
        "resolved_ips": addresses,
        "http_status": response["status_code"],
        "tls": tls,
        "headers": header_analysis,
        "technologies": technology_analysis,
        "cookie_security": analyze_cookie_security(response["headers"]),
        "findings": findings,
        "risk_level": risk,
        "security_score": security_score,
        "summary": {
            "high": high,
            "medium": medium,
            "total": len(findings),
        },
        **(
            {
                "_analysis_context": {
                    "html_content": response["content"],
                    "response_headers": response["headers"],
                }
            }
            if include_page_content
            else {}
        ),
    }
