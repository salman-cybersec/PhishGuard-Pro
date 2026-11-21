import pytest

from phishguard.security_score import calculate_security_score


def test_empty_findings_returns_perfect_score():
    result = calculate_security_score([])

    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["total_deduction"] == 0


def test_mixed_severity_deductions():
    result = calculate_security_score([
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
    ])

    assert result["score"] == 49
    assert result["grade"] == "F"
    assert result["total_deduction"] == 51


def test_score_never_goes_below_zero():
    result = calculate_security_score([
        {"severity": "critical"},
        {"severity": "critical"},
        {"severity": "critical"},
        {"severity": "critical"},
        {"severity": "critical"},
    ])

    assert result["score"] == 0
    assert result["grade"] == "F"


def test_severity_is_case_insensitive():
    result = calculate_security_score([
        {"severity": "HIGH"},
        {"severity": "Medium"},
    ])

    assert result["score"] == 77
    assert result["breakdown"]["high"] == 1
    assert result["breakdown"]["medium"] == 1


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        calculate_security_score([{"severity": "unknown"}])


def test_invalid_findings_entry_is_rejected():
    with pytest.raises(ValueError):
        calculate_security_score(["invalid"])


def test_non_list_findings_are_rejected():
    with pytest.raises(ValueError):
        calculate_security_score(None)
