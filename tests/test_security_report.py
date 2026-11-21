from pathlib import Path

from phishguard import security_report


def sample_result():
    return {
        "hostname": "example.com",
        "url": "https://example.com/",
        "http_status": 200,
        "resolved_ips": ["8.8.8.8"],
        "tls": {
            "version": "TLSv1.3",
            "expires_at": "2027-01-01T00:00:00+00:00",
            "days_remaining": 100,
        },
        "headers": {
            "present": ["HSTS", "CSP"],
            "missing": ["X-Frame-Options"],
        },
        "findings": [
            {
                "severity": "medium",
                "finding": "Missing X-Frame-Options header",
                "remediation": "Set X-Frame-Options to DENY.",
            }
        ],
        "risk_level": "medium",
    }


def test_html_report_created(monkeypatch, tmp_path):
    monkeypatch.setattr(security_report, "REPORT_DIR", tmp_path)

    result = security_report.export_security_html_report(
        sample_result()
    )

    report = Path(result["html_report"])

    assert report.exists()
    assert report.suffix == ".html"
    assert result["hostname"] == "example.com"
    assert result["total_findings"] == 1

    content = report.read_text(encoding="utf-8")
    assert "Website Security Analysis Report" in content
    assert "Missing X-Frame-Options header" in content
    assert "Set X-Frame-Options to DENY." in content


def test_html_report_escapes_untrusted_content(monkeypatch, tmp_path):
    monkeypatch.setattr(security_report, "REPORT_DIR", tmp_path)

    result = sample_result()
    result["hostname"] = "<script>alert(1)</script>"

    report = security_report.export_security_html_report(result)
    content = Path(report["html_report"]).read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content


def test_invalid_result_rejected():
    import pytest

    with pytest.raises(ValueError):
        security_report.export_security_html_report("invalid")


def test_invalid_findings_rejected():
    import pytest

    result = sample_result()
    result["findings"] = "invalid"

    with pytest.raises(ValueError):
        security_report.export_security_html_report(result)


def test_json_report_created(monkeypatch, tmp_path):
    import json

    monkeypatch.setattr(security_report, "REPORT_DIR", tmp_path)

    original = sample_result()
    result = security_report.export_security_json_report(original)

    report = Path(result["json_report"])

    assert report.exists()
    assert report.suffix == ".json"
    assert result["hostname"] == "example.com"
    assert result["total_findings"] == 1

    data = json.loads(report.read_text(encoding="utf-8"))

    assert data["report_type"] == "PhishGuard Pro Security Scan"
    assert data["hostname"] == "example.com"
    assert data["findings"][0]["finding"] == "Missing X-Frame-Options header"
    assert data["tls"]["version"] == "TLSv1.3"
    assert "generated_at" in data


def test_json_report_preserves_original_result(monkeypatch, tmp_path):
    import copy

    monkeypatch.setattr(security_report, "REPORT_DIR", tmp_path)

    original = sample_result()
    original_copy = copy.deepcopy(original)

    security_report.export_security_json_report(original)

    assert original == original_copy


def test_json_report_rejects_invalid_data():
    import pytest

    with pytest.raises(ValueError):
        security_report.export_security_json_report("invalid")

    result = sample_result()
    result["findings"] = "invalid"

    with pytest.raises(ValueError):
        security_report.export_security_json_report(result)


def test_html_and_json_report_filenames_are_unique(monkeypatch, tmp_path):
    monkeypatch.setattr(security_report, "REPORT_DIR", tmp_path)

    result = sample_result()

    html_first = security_report.export_security_html_report(result)
    html_second = security_report.export_security_html_report(result)

    json_first = security_report.export_security_json_report(result)
    json_second = security_report.export_security_json_report(result)

    assert html_first["html_report"] != html_second["html_report"]
    assert json_first["json_report"] != json_second["json_report"]


def test_json_report_rejects_invalid_tls_metadata():
    import pytest

    result = sample_result()
    result["tls"] = "invalid"

    with pytest.raises(ValueError):
        security_report.export_security_json_report(result)


def test_json_report_rejects_invalid_headers_metadata():
    import pytest

    result = sample_result()
    result["headers"] = "invalid"

    with pytest.raises(ValueError):
        security_report.export_security_json_report(result)
