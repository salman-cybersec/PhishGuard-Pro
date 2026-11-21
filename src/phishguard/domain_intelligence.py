"""Passive domain, DNS and RDAP intelligence for authorized assessments."""

import ipaddress
import re

import dns.resolver
import httpx


DNS_TIMEOUT = 3
RDAP_TIMEOUT = 8
MAX_RDAP_BYTES = 1_000_000


def _validate_domain(domain):
    domain = str(domain).strip().rstrip(".").encode("idna").decode("ascii").lower()

    if len(domain) > 253 or "." not in domain:
        raise ValueError("A valid fully-qualified domain is required.")

    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid domain name.")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain

    raise ValueError("An IP address is not a domain name.")


def _query_dns(domain, record_type):
    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=DNS_TIMEOUT,
        )

        values = []
        for record in answers:
            if record_type == "MX":
                values.append({
                    "priority": record.preference,
                    "host": str(record.exchange).rstrip("."),
                })
            elif record_type == "CAA":
                values.append({
                    "flags": record.flags,
                    "tag": record.tag,
                    "value": record.value,
                })
            else:
                values.append(record.to_text().strip('"'))

        return {"status": "found", "records": values}

    except dns.resolver.NXDOMAIN:
        return {"status": "not_found", "records": []}
    except dns.resolver.NoAnswer:
        return {"status": "not_found", "records": []}
    except Exception:
        return {"status": "unavailable", "records": []}


def _lookup_rdap(domain):
    """Look up public registration events through the RDAP bootstrap service."""
    endpoint = f"https://rdap.org/domain/{domain}"

    try:
        with httpx.Client(
            timeout=RDAP_TIMEOUT,
            follow_redirects=False,
            max_redirects=3,
            trust_env=False,
            headers={"User-Agent": "PhishGuard-Pro-Domain-Intelligence/1.0"},
        ) as client:
            response = client.get(endpoint)

        if response.status_code != 200:
            return {"status": "unavailable"}

        if len(response.content) > MAX_RDAP_BYTES:
            return {"status": "unavailable"}

        data = response.json()
        events = {}

        for event in data.get("events", []):
            action = str(event.get("eventAction", "")).lower()
            date = event.get("eventDate")

            if action in ("registration", "expiration", "last changed"):
                events[action] = date

        registrar = None
        for entity in data.get("entities", []):
            if "registrar" not in entity.get("roles", []):
                continue

            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if len(item) >= 4 and item[0] in ("fn", "org"):
                        registrar = item[3]
                        break
            if registrar:
                break

        nameservers = [
            item.get("ldhName")
            for item in data.get("nameservers", [])
            if item.get("ldhName")
        ]

        return {
            "status": "found",
            "registrar": registrar,
            "registration_date": events.get("registration"),
            "expiration_date": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "nameservers": nameservers,
        }

    except Exception:
        return {"status": "unavailable"}


def _ip_details(addresses):
    results = []

    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
            results.append({
                "address": str(parsed),
                "version": f"IPv{parsed.version}",
                "is_global": parsed.is_global,
                "is_private": parsed.is_private,
            })
        except ValueError:
            continue

    return results


def _hosting_indicators(nameservers):
    indicators = []
    providers = {
        "cloudflare": "Cloudflare",
        "awsdns": "Amazon Route 53",
        "amazonaws": "Amazon Web Services",
        "azure-dns": "Microsoft Azure DNS",
        "googledomains": "Google",
        "domaincontrol": "GoDaddy",
        "vercel-dns": "Vercel",
        "netlify": "Netlify",
    }

    for nameserver in nameservers:
        value = nameserver.lower()
        for marker, provider in providers.items():
            if marker in value and provider not in indicators:
                indicators.append(provider)

    return indicators


def analyze_domain_intelligence(domain, resolved_ips=None):
    """Collect passive DNS, IP, RDAP and hosting information."""
    domain = _validate_domain(domain)

    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
    dns_records = {
        record_type: _query_dns(domain, record_type)
        for record_type in record_types
    }

    if resolved_ips is None:
        addresses = (
            dns_records["A"]["records"]
            + dns_records["AAAA"]["records"]
        )
    else:
        addresses = list(resolved_ips)

    ip_details = _ip_details(addresses)
    nameservers = dns_records["NS"]["records"]

    txt_records = dns_records["TXT"]["records"]
    spf_records = [
        value for value in txt_records
        if value.lower().startswith("v=spf1")
    ]

    dmarc = _query_dns(f"_dmarc.{domain}", "TXT")
    dmarc_records = [
        value for value in dmarc["records"]
        if value.lower().startswith("v=dmarc1")
    ]

    rdap = _lookup_rdap(domain)

    return {
        "domain": domain,
        "dns": dns_records,
        "ip_addresses": ip_details,
        "email_security": {
            "spf": {
                "status": "found" if spf_records else (
                    "not_found" if dns_records["TXT"]["status"] == "found"
                    else dns_records["TXT"]["status"]
                ),
                "records": spf_records,
            },
            "dmarc": {
                "status": "found" if dmarc_records else dmarc["status"],
                "records": dmarc_records,
            },
        },
        "registration": rdap,
        "hosting_indicators": _hosting_indicators(
            nameservers + rdap.get("nameservers", [])
        ),
        "source": "Public DNS records and RDAP",
        "scan_type": "passive_domain_intelligence",
    }
