"""
Assign risk scores and overall posture rating to a set of findings.
"""

from typing import Dict, List

SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

MAX_SCORE = 100


def score_findings(findings: List[dict]) -> Dict:
    """Return overall risk score (0-100), grade, and per-severity breakdown."""
    if not findings:
        return {"score": 0, "grade": "A", "breakdown": {}}

    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    raw = 0
    for f in findings:
        sev = f.get("severity", "info")
        breakdown[sev] = breakdown.get(sev, 0) + 1
        raw += SEVERITY_WEIGHTS.get(sev, 0)

    # Normalize to 0-100 (cap at 100)
    max_raw = len(findings) * 10
    score = min(100, int((raw / max_raw) * 100)) if max_raw else 0

    grade = _grade(score)
    return {"score": score, "grade": grade, "breakdown": breakdown}


def _grade(score: int) -> str:
    if score <= 10:
        return "A"
    if score <= 30:
        return "B"
    if score <= 50:
        return "C"
    if score <= 70:
        return "D"
    return "F"
