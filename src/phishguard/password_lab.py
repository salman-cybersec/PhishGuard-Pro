
import re


COMMON_TEST_PASSWORDS = {
    "test123",
    "sample123",
    "admin123",
    "password123",
    "welcome123",
    "qwerty123",
}


def analyze_password(password: str) -> dict:
    if not isinstance(password, str):
        raise ValueError("Password must be text.")

    if not password:
        raise ValueError("Password cannot be empty.")

    if len(password) > 128:
        raise ValueError("Test password cannot exceed 128 characters.")

    checks = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"[0-9]", password)),
        "special_character": bool(
            re.search(r"[^A-Za-z0-9]", password)
        ),
    }

    score = sum(checks.values())

    if password.lower() in COMMON_TEST_PASSWORDS:
        strength = "Weak"
    elif score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return {
        "length": len(password),
        "checks": checks,
        "score": score,
        "strength": strength,
        "is_common_test_password": (
            password.lower() in COMMON_TEST_PASSWORDS
        ),
        "stored": False,
    }
