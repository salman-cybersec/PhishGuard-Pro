"""Passive DNS and email-domain security assessment."""

import re

from phishguard.domain_intelligence import (
    _validate_domain,
    _query_dns,
)


def _finding(severity, name, evidence, remediation):
    return {
        "severity": severity,
        "finding": name,
        "evidence": evidence,
        "remediation": remediation,
    }


def _analyze_spf(records, status):
    findings = []

    if status == "unavailable":
        return {"status": "unavailable", "records": records, "findings": findings}

    if not records:
        findings.append(_finding(
            "medium",
            "SPF record not detected",
            "No SPF TXT record was found.",
            "Publish an SPF record if this domain sends email."
        ))
        return {"status": "missing", "records": [], "findings": findings}

    if len(records) > 1:
        findings.append(_finding(
            "high",
            "Multiple SPF records detected",
            f"{len(records)} SPF records were found.",
            "Merge authorized senders into one SPF record."
        ))

    for record in records:
        mechanisms = record.lower().split()

        if "+all" in mechanisms or "all" in mechanisms:
            findings.append(_finding(
                "high",
                "SPF policy permits all senders",
                record,
                "Replace the permissive all mechanism with an appropriate restrictive policy."
            ))
        elif "?all" in mechanisms:
            findings.append(_finding(
                "medium",
                "SPF policy uses neutral all",
                record,
                "Review authorized senders and consider an appropriate enforcement policy."
            ))
        elif "~all" in mechanisms:
            findings.append(_finding(
                "low",
                "SPF policy uses softfail",
                record,
                "Review whether a stricter SPF policy is appropriate."
            ))

    return {
        "status": "found",
        "records": records,
        "findings": findings,
    }


def _analyze_dmarc(records, status):
    findings = []

    if status == "unavailable":
        return {"status": "unavailable", "records": records, "policy": None, "findings": findings}

    if not records:
        findings.append(_finding(
            "medium",
            "DMARC record not detected",
            "No valid DMARC TXT record was found at _dmarc.",
            "Publish a DMARC record after reviewing SPF and DKIM alignment."
        ))
        return {"status": "missing", "records": [], "policy": None, "findings": findings}

    if len(records) > 1:
        findings.append(_finding(
            "high",
            "Multiple DMARC records detected",
            f"{len(records)} DMARC records were found.",
            "Maintain one valid DMARC policy record."
        ))

    record = records[0]
    match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b", record, re.I)
    policy = match.group(1).lower() if match else None

    if not policy:
        findings.append(_finding(
            "high",
            "DMARC policy is missing or invalid",
            record,
            "Configure a valid DMARC p policy."
        ))
    elif policy == "none":
        findings.append(_finding(
            "medium",
            "DMARC is in monitoring mode",
            f"Current policy: p={policy}",
            "Review aggregate reports and consider moving to quarantine or reject when ready."
        ))

    return {
        "status": "found",
        "records": records,
        "policy": policy,
        "findings": findings,
    }


def _analyze_caa(records, status):
    findings = []

    if status == "unavailable":
        return {"status": "unavailable", "records": records, "findings": findings}

    if not records:
        findings.append(_finding(
            "low",
            "CAA records not detected",
            "No CAA record was found.",
            "Consider publishing CAA records to restrict which certificate authorities may issue certificates."
        ))
        return {"status": "missing", "records": [], "findings": findings}

    return {"status": "found", "records": records, "findings": findings}


def _analyze_mx(records, status):
    findings = []

    if status == "unavailable":
        return {"status": "unavailable", "records": records, "findings": findings}

    if not records:
        return {
            "status": "not_detected",
            "records": [],
            "findings": [],
        }

    return {"status": "found", "records": records, "findings": findings}


def _analyze_dkim(domain, selector):
    if not selector:
        return {
            "status": "not_checked",
            "selector": None,
            "records": [],
            "findings": [],
        }

    selector = str(selector).strip().lower()

    if (
        len(selector) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", selector)
    ):
        raise ValueError("Invalid DKIM selector.")

    hostname = f"{selector}._domainkey.{domain}"
    result = _query_dns(hostname, "TXT")
    records = [
        item for item in result["records"]
        if "v=dkim1" in item.lower() or "p=" in item.lower()
    ]

    if result["status"] == "unavailable":
        status = "unavailable"
    elif records:
        status = "found"
    else:
        status = "not_detected"

    return {
        "status": status,
        "selector": selector,
        "records": records,
        "findings": [],
    }


def analyze_dns_security(domain, dns_data=None, dkim_selector=None):
    """Assess DNS and email security using passive DNS queries only."""
    domain = _validate_domain(domain)

    if dns_data is None:
        txt = _query_dns(domain, "TXT")
        dmarc = _query_dns(f"_dmarc.{domain}", "TXT")
        caa = _query_dns(domain, "CAA")
        mx = _query_dns(domain, "MX")
        dns_data = {
            "TXT": txt,
            "DMARC": dmarc,
            "CAA": caa,
            "MX": mx,
        }

    txt = dns_data.get("TXT", {"status": "unavailable", "records": []})
    dmarc = dns_data.get("DMARC", {"status": "unavailable", "records": []})
    caa = dns_data.get("CAA", {"status": "unavailable", "records": []})
    mx = dns_data.get("MX", {"status": "unavailable", "records": []})

    spf_records = [
        item for item in txt["records"]
        if isinstance(item, str) and item.lower().startswith("v=spf1")
    ]
    dmarc_records = [
        item for item in dmarc["records"]
        if isinstance(item, str) and item.lower().startswith("v=dmarc1")
    ]

    results = {
        "domain": domain,
        "spf": _analyze_spf(spf_records, txt["status"]),
        "dmarc": _analyze_dmarc(dmarc_records, dmarc["status"]),
        "caa": _analyze_caa(caa["records"], caa["status"]),
        "mx": _analyze_mx(mx["records"], mx["status"]),
        "dkim": _analyze_dkim(domain, dkim_selector),
        "source": "Passive DNS queries",
        "scan_type": "dns_security_assessment",
    }

    all_findings = []
    for section in ("spf", "dmarc", "caa", "mx", "dkim"):
        all_findings.extend(results[section]["findings"])

    results["findings"] = all_findings
    results["summary"] = {
        "total_findings": len(all_findings),
        "high": sum(f["severity"] == "high" for f in all_findings),
        "medium": sum(f["severity"] == "medium" for f in all_findings),
        "low": sum(f["severity"] == "low" for f in all_findings),
    }

    return results
