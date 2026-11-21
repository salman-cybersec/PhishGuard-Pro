"""Combined passive security assessment for authorized HTTPS websites."""

import dns.resolver

from phishguard.security_analyzer import analyze_website
from phishguard.security_score import calculate_security_score
from phishguard.subdomain_discovery import discover_subdomains


def analyze_dns_security(hostname: str) -> dict:
    """Check SPF and DMARC TXT records without changing DNS."""
    checks = {}
    findings = []

    def lookup_txt(name):
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=4)
            return [
                b"".join(record.strings).decode("utf-8", errors="replace")
                for record in answers
            ], None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], None
        except Exception as error:
            return None, type(error).__name__

    spf_records, spf_error = lookup_txt(hostname)

    if spf_error:
        checks["spf"] = {"status": "unavailable", "error": spf_error}
    else:
        spf = [record for record in spf_records
               if record.lower().startswith("v=spf1")]

        if not spf:
            checks["spf"] = {"status": "missing", "records": 0}
            findings.append({
                "severity": "medium",
                "finding": "No SPF record found",
                "remediation": "Publish an SPF TXT record listing the mail servers authorized to send email for this domain.",
            })
        elif len(spf) > 1:
            checks["spf"] = {"status": "multiple", "records": len(spf)}
            findings.append({
                "severity": "medium",
                "finding": "Multiple SPF records found",
                "remediation": "Consolidate SPF mechanisms into a single SPF TXT record for the domain.",
            })
        else:
            checks["spf"] = {"status": "present", "records": 1}

    dmarc_records, dmarc_error = lookup_txt("_dmarc." + hostname)

    if dmarc_error:
        checks["dmarc"] = {"status": "unavailable", "error": dmarc_error}
    else:
        dmarc = [record for record in dmarc_records
                 if record.lower().startswith("v=dmarc1")]

        if not dmarc:
            checks["dmarc"] = {"status": "missing", "records": 0}
            findings.append({
                "severity": "medium",
                "finding": "No DMARC record found",
                "remediation": "Publish a DMARC TXT record at _dmarc with a policy appropriate for your domain.",
            })
        else:
            policies = [
                part.strip().lower()
                for part in dmarc[0].split(";")
                if part.strip().lower().startswith("p=")
            ]
            policy = policies[0][2:] if policies else "unspecified"
            checks["dmarc"] = {
                "status": "present",
                "policy": policy,
                "records": len(dmarc),
            }

            if policy == "none":
                findings.append({
                    "severity": "low",
                    "finding": "DMARC policy is set to monitoring only (p=none)",
                    "remediation": "Review DMARC reports and consider moving to quarantine or reject when legitimate mail sources are aligned.",
                })

    return {"checks": checks, "findings": findings}


SCAN_MODES = {
    "fast": 50,
    "extended": 200,
    "thorough": 500,
}


def analyze_full_website(url: str, *, scan_mode: str = "fast") -> dict:
    """Run passive website checks with a configurable subdomain processing limit."""
    if scan_mode not in SCAN_MODES:
        raise ValueError(
            "scan_mode must be one of: fast, extended, thorough."
        )

    result = analyze_website(url)
    subdomain_analysis = discover_subdomains(
        result["hostname"],
        max_subdomains=SCAN_MODES[scan_mode],
    )

    dns_analysis = analyze_dns_security(result["hostname"])
    cookie_analysis = result.get(
        "cookie_security",
        {"cookies": [], "count": 0, "findings": []},
    )

    extra_findings = (
        dns_analysis["findings"]
        + cookie_analysis.get("findings", [])
    )

    findings = list(result["findings"]) + extra_findings
    score = calculate_security_score(findings)

    counts = {
        severity: sum(
            item.get("severity") == severity for item in findings
        )
        for severity in ("critical", "high", "medium", "low")
    }

    risk = (
        "high" if counts["critical"] or counts["high"] else
        "medium" if counts["medium"] else
        "low"
    )

    result.update({
        "findings": findings,
        "security_score": score,
        "risk_level": risk,
        "summary": {**counts, "total": len(findings)},
        "checks": {
            "https": {
                "status": "completed",
                "http_status": result["http_status"],
            },
            "tls": result["tls"],
            "headers": result["headers"],
            "technologies": result["technologies"],
            "cookies": cookie_analysis,
            "dns": dns_analysis,
            "subdomains": subdomain_analysis,
        },
        "scan_type": "full",
        "scan_mode": scan_mode,
        "subdomain_limit": SCAN_MODES[scan_mode],
    })

    return result
