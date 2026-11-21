SEVERITY_PENALTIES = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


def calculate_security_score(findings: list) -> dict:
    if not isinstance(findings, list):
        raise ValueError("Findings must be a list.")

    breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("Invalid finding entry.")

        severity = item.get("severity")

        if not isinstance(severity, str):
            raise ValueError("Finding severity must be a string.")

        severity = severity.lower()

        if severity not in SEVERITY_PENALTIES:
            raise ValueError(f"Unsupported severity: {severity}")

        breakdown[severity] += 1

    deductions = {
        severity: count * SEVERITY_PENALTIES[severity]
        for severity, count in breakdown.items()
    }

    total_deduction = sum(deductions.values())
    score = max(0, min(100, 100 - total_deduction))

    return {
        "score": score,
        "grade": (
            "A" if score >= 90 else
            "B" if score >= 80 else
            "C" if score >= 70 else
            "D" if score >= 60 else
            "F"
        ),
        "breakdown": breakdown,
        "deductions": deductions,
        "total_deduction": total_deduction,
    }
