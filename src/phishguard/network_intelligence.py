"""Passive public IP and network intelligence using DNS lookups."""

import ipaddress

import dns.exception
import dns.resolver


def _validate_ip(address):
    try:
        return ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("A valid IPv4 or IPv6 address is required.") from exc


def _cymru_query_name(address):
    parsed = _validate_ip(address)

    if not parsed.is_global:
        raise ValueError("Network intelligence is only available for public IP addresses.")

    if parsed.version == 4:
        reversed_ip = ".".join(reversed(str(parsed).split(".")))
        return f"{reversed_ip}.origin.asn.cymru.com"

    reversed_nibbles = ".".join(reversed(parsed.exploded.replace(":", "")))
    return f"{reversed_nibbles}.origin6.asn.cymru.com"


def _lookup_asn(address):
    try:
        query_name = _cymru_query_name(address)
        answers = dns.resolver.resolve(query_name, "TXT", lifetime=4)

        records = []
        for answer in answers:
            value = answer.to_text().strip('"')
            parts = [part.strip() for part in value.split("|")]

            if len(parts) < 5:
                continue

            records.append({
                "asn": parts[0],
                "network": parts[1],
                "country": parts[2],
                "registry": parts[3],
                "allocation_date": parts[4],
                "organization": parts[5] if len(parts) > 5 else "Not disclosed",
            })

        if records:
            return {"status": "found", "records": records}

        return {"status": "not_found", "records": []}

    except (ValueError, dns.exception.DNSException, OSError):
        return {"status": "unavailable", "records": []}
    except Exception:
        return {"status": "unavailable", "records": []}


def _lookup_reverse_dns(address):
    try:
        parsed = _validate_ip(address)

        if not parsed.is_global:
            return {"status": "not_applicable", "records": []}

        reverse_name = parsed.reverse_pointer
        answers = dns.resolver.resolve(reverse_name, "PTR", lifetime=4)
        records = sorted({answer.to_text().rstrip(".") for answer in answers})

        return {
            "status": "found" if records else "not_found",
            "records": records,
        }

    except (ValueError, dns.exception.DNSException, OSError):
        return {"status": "unavailable", "records": []}
    except Exception:
        return {"status": "unavailable", "records": []}


def analyze_ip_network(address):
    """Collect passive ASN, network and reverse-DNS details for a public IP."""
    parsed = _validate_ip(address)

    result = {
        "address": str(parsed),
        "version": f"IPv{parsed.version}",
        "is_global": parsed.is_global,
        "is_private": parsed.is_private,
        "is_reserved": parsed.is_reserved,
    }

    if not parsed.is_global:
        result.update({
            "asn": {"status": "not_applicable", "records": []},
            "reverse_dns": {"status": "not_applicable", "records": []},
            "source": "Python IP address classification",
        })
        return result

    result.update({
        "asn": _lookup_asn(str(parsed)),
        "reverse_dns": _lookup_reverse_dns(str(parsed)),
        "source": "Team Cymru IP-to-ASN DNS service and public PTR DNS records",
    })

    return result


def analyze_network_addresses(addresses):
    """Analyze unique IP addresses and skip invalid entries."""
    results = []
    seen = set()

    for address in addresses:
        try:
            parsed = _validate_ip(address)
        except (ValueError, TypeError):
            continue

        normalized = str(parsed)
        if normalized in seen:
            continue

        seen.add(normalized)
        results.append(analyze_ip_network(normalized))

    return results
