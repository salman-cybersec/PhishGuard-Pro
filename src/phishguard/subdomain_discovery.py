"""Passive subdomain discovery using Certificate Transparency records."""

import ipaddress
import re

import dns.exception
import dns.resolver
import httpx


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SUBDOMAINS = 500
CT_ENDPOINT = "https://crt.sh/"


def _validate_domain(domain):
    if not isinstance(domain, str):
        raise ValueError("A valid domain is required.")

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253 or "*" in domain:
        raise ValueError("Invalid domain.")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid domain.") from exc

    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("A fully qualified domain is required.")

    pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not pattern.fullmatch(label) for label in labels):
        raise ValueError("Invalid domain.")

    return domain


def _extract_subdomains(domain, entries, max_subdomains=MAX_SUBDOMAINS):
    discovered = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        names = entry.get("name_value", "")
        if not isinstance(names, str):
            continue

        for raw_name in names.splitlines():
            hostname = raw_name.strip().lower().rstrip(".")
            if hostname.startswith("*."):
                hostname = hostname[2:]

            try:
                hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                continue

            if len(hostname) > 253:
                continue

            labels = hostname.split(".")
            if any(
                not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                    label,
                )
                for label in labels
            ):
                continue

            if hostname == domain:
                continue

            if not hostname.endswith("." + domain):
                continue

            discovered.setdefault(hostname, set()).add("Certificate Transparency")

    return discovered


def _query_certificate_transparency(domain):
    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json", "User-Agent": "PhishGuard-Pro/0.1"},
        ) as client:
            response = client.get(
                CT_ENDPOINT,
                params={"q": f"%.{domain}", "output": "json"},
            )

        if response.status_code != 200:
            return {"status": "unavailable", "records": []}

        if len(response.content) > MAX_RESPONSE_BYTES:
            return {"status": "response_too_large", "records": []}

        data = response.json()
        if not isinstance(data, list):
            return {"status": "invalid_response", "records": []}

        return {"status": "found", "records": data}

    except (httpx.HTTPError, ValueError, OSError):
        return {"status": "unavailable", "records": []}
    except Exception:
        return {"status": "unavailable", "records": []}


def _resolve_subdomain(hostname):
    result = {"A": [], "AAAA": []}

    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=3,
            )
            for answer in answers:
                address = str(ipaddress.ip_address(answer.to_text()))
                if ipaddress.ip_address(address).is_global:
                    result[record_type].append(address)

        except (dns.exception.DNSException, OSError, ValueError):
            continue

    result["A"] = sorted(set(result["A"]))
    result["AAAA"] = sorted(set(result["AAAA"]))
    result["status"] = "resolved" if result["A"] or result["AAAA"] else "not_resolved"

    return result


def discover_subdomains(domain, max_subdomains=MAX_SUBDOMAINS):
    """Discover CT-listed names and resolve only up to the selected limit."""
    domain = _validate_domain(domain)

    if (
        isinstance(max_subdomains, bool)
        or not isinstance(max_subdomains, int)
        or not 1 <= max_subdomains <= MAX_SUBDOMAINS
    ):
        raise ValueError(
            f"max_subdomains must be an integer between 1 and {MAX_SUBDOMAINS}."
        )

    ct_result = _query_certificate_transparency(domain)

    if ct_result["status"] != "found":
        return {
            "domain": domain,
            "source_status": ct_result["status"],
            "max_subdomains": max_subdomains,
            "total_discovered": 0,
            "total_processed": 0,
            "total_resolved": 0,
            "total_unresolved": 0,
            "truncated": False,
            "subdomains": [],
            "source": "Certificate Transparency via crt.sh",
        }

    discovered = _extract_subdomains(domain, ct_result["records"])
    selected = sorted(discovered)[:max_subdomains]
    results = []

    for hostname in selected:
        dns_result = _resolve_subdomain(hostname)
        results.append({
            "hostname": hostname,
            "sources": sorted(discovered[hostname]),
            "dns": dns_result,
        })

    resolved = sum(
        item["dns"]["status"] == "resolved" for item in results
    )
    total_discovered = len(discovered)
    total_processed = len(results)

    return {
        "domain": domain,
        "source_status": "found",
        "max_subdomains": max_subdomains,
        "total_discovered": total_discovered,
        "total_processed": total_processed,
        "total_resolved": resolved,
        "total_unresolved": total_processed - resolved,
        "truncated": total_discovered > total_processed,
        "subdomains": results,
        "source": "Certificate Transparency via crt.sh and public DNS",
    }
