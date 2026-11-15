import pytest

from phishguard.security import validate_input


def test_normal_input_is_safe():
    result = validate_input("Hello PhishGuard Pro")

    assert result["valid"] is True
    assert result["suspicious"] is False


def test_xss_pattern_is_detected():
    result = validate_input("<script>alert(1)</script>")

    assert result["suspicious"] is True
    assert "xss" in result["findings"]


def test_sql_injection_pattern_is_detected():
    result = validate_input("' OR 1=1 --")

    assert result["suspicious"] is True
    assert "sql_injection" in result["findings"]


def test_oversized_input_is_rejected():
    with pytest.raises(ValueError):
        validate_input("A" * 2001)


def test_non_string_input_is_rejected():
    with pytest.raises(ValueError):
        validate_input(123)
