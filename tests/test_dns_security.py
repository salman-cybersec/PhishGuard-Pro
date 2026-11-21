import pytest

from phishguard import dns_security as dns


def test_missing_email_security_records():
    result = dns.analyze_dns_security(
        "example.com",
        dns_data={
            "TXT": {"status": "found", "records": ["hello=world"]},
            "DMARC": {"status": "not_found", "records": []},
            "CAA": {"status": "not_found", "records": []},
            "MX": {"status": "not_found", "records": []},
        },
    )

    assert result["spf"]["status"] == "missing"
    assert result["dmarc"]["status"] == "missing"
    assert result["caa"]["status"] == "missing"
    assert result["mx"]["status"] == "not_detected"
    assert result["summary"]["total_findings"] == 3


def test_permissive_spf_is_high_severity():
    result = dns._analyze_spf(
        ["v=spf1 +all"],
        "found",
    )

    assert any(item["severity"] == "high" for item in result["findings"])


def test_multiple_spf_records_are_flagged():
    result = dns._analyze_spf(
        ["v=spf1 include:a.example.com -all", "v=spf1 include:b.example.com -all"],
        "found",
    )

    assert result["findings"][0]["severity"] == "high"


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=DMARC1; p=none", "none"),
        ("v=DMARC1; p=quarantine", "quarantine"),
        ("v=DMARC1; p=reject", "reject"),
    ],
)
def test_dmarc_policy_detection(record, expected):
    result = dns._analyze_dmarc([record], "found")
    assert result["policy"] == expected


def test_dmarc_none_policy_is_flagged():
    result = dns._analyze_dmarc(["v=DMARC1; p=none"], "found")

    assert result["findings"][0]["severity"] == "medium"


def test_dkim_is_not_guessed_without_selector():
    result = dns._analyze_dkim("example.com", None)

    assert result["status"] == "not_checked"


def test_dkim_selector_validation():
    with pytest.raises(ValueError):
        dns._analyze_dkim("example.com", "../bad")


def test_dkim_selector_lookup(monkeypatch):
    monkeypatch.setattr(
        dns,
        "_query_dns",
        lambda hostname, record_type: {
            "status": "found",
            "records": ["v=DKIM1; p=publickey"],
        },
    )

    result = dns._analyze_dkim("example.com", "selector1")

    assert result["status"] == "found"
    assert result["selector"] == "selector1"


def test_unavailable_dns_is_not_reported_as_missing():
    result = dns.analyze_dns_security(
        "example.com",
        dns_data={
            "TXT": {"status": "unavailable", "records": []},
            "DMARC": {"status": "unavailable", "records": []},
            "CAA": {"status": "unavailable", "records": []},
            "MX": {"status": "unavailable", "records": []},
        },
    )

    assert result["spf"]["status"] == "unavailable"
    assert result["dmarc"]["status"] == "unavailable"
    assert result["caa"]["status"] == "unavailable"
    assert result["findings"] == []


def test_invalid_domain_rejected():
    with pytest.raises(ValueError):
        dns.analyze_dns_security("localhost")
