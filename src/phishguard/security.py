
import re
from html import escape


MAX_INPUT_LENGTH = 2000

SUSPICIOUS_PATTERNS = {
    "sql_injection": re.compile(
        r"(\bunion\s+select\b|--|/\*|\bor\s+1\s*=\s*1\b)",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=)",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"(\.\.[/\\]|%2e%2e[/\\])",
        re.IGNORECASE,
    ),
    "command_injection": re.compile(
        r"(;\s*(cat|curl|wget|rm|whoami)\b|\|\s*(cat|curl|wget)\b)",
        re.IGNORECASE,
    ),
}


def validate_input(value: str) -> dict:
    if not isinstance(value, str):
        raise ValueError("Input must be text.")

    if not value.strip():
        raise ValueError("Input cannot be empty.")

    if len(value) > MAX_INPUT_LENGTH:
        raise ValueError("Input exceeds the maximum length.")

    if "\x00" in value:
        raise ValueError("Null bytes are not allowed.")

    findings = []

    for category, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(value):
            findings.append(category)

    return {
        "valid": True,
        "suspicious": bool(findings),
        "findings": findings,
        "safe_display": escape(value),
        "length": len(value),
    }
