from collections import Counter
from typing import TypedDict

from .models import Finding, SeverityLevel

WEIGHT_CRITICAL: int = 40
WEIGHT_HIGH: int = 15
WEIGHT_MEDIUM: int = 5
WEIGHT_LOW: int = 1

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": WEIGHT_CRITICAL,
    "high": WEIGHT_HIGH,
    "medium": WEIGHT_MEDIUM,
    "low": WEIGHT_LOW,
}

DIMINISHING_THRESHOLD: int = 5
DIMINISHING_FACTOR: float = 0.25


class SeverityBreakdown(TypedDict):
    critical: int
    high: int
    medium: int
    low: int


class RiskAssessment(TypedDict):
    score: int
    raw_score: float
    level: SeverityLevel
    breakdown: SeverityBreakdown
    status: str


def calculate_risk(findings: list[Finding]) -> RiskAssessment:
    """Calculate risk score (0-100), risk level, and severity breakdown from scan findings.

    Applies diminishing returns to repeated findings of the same type and severity
    to ensure individual noisy rules cannot alone saturate the score prematurely.
    """
    breakdown: SeverityBreakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    if not findings:
        return {
            "score": 0,
            "raw_score": 0.0,
            "level": "low",
            "breakdown": breakdown,
            "status": "passed",
        }

    for f in findings:
        sev = f.severity.lower()
        if sev in breakdown:
            breakdown[sev] += 1  # type: ignore[literal-required]

    # Calculate contribution grouped by type with diminishing returns after 5 findings
    type_counts = Counter(f.type for f in findings)
    type_to_severity = {f.type: f.severity.lower() for f in findings}

    raw_score = 0.0
    for finding_type, count in type_counts.items():
        base_weight = SEVERITY_WEIGHTS.get(type_to_severity[finding_type], WEIGHT_LOW)
        if count <= DIMINISHING_THRESHOLD:
            raw_score += count * base_weight
        else:
            raw_score += (DIMINISHING_THRESHOLD * base_weight) + (
                (count - DIMINISHING_THRESHOLD) * base_weight * DIMINISHING_FACTOR
            )

    # Scale score progressively towards 100 ceiling
    if raw_score <= 70:
        score = int(round(raw_score))
    else:
        # Taper smoothly between 70 and 100 so multi-critical workloads order correctly
        excess = raw_score - 70
        tapered = 70 + (30 * (1 - (0.95 ** (excess / 5))))
        score = min(100, int(round(tapered)))

    # Ensure score reflects critical existence
    if breakdown["critical"] > 0:
        score = max(score, WEIGHT_CRITICAL)

    # Determine risk level
    if score >= 70 or breakdown["critical"] >= 2:
        level: SeverityLevel = "critical"
    elif score >= 40 or breakdown["critical"] >= 1:
        level = "high"
    elif score >= 15:
        level = "medium"
    else:
        level = "low"

    # Block rule: status = "blocked" if score >= 40 OR any critical finding; else "passed"
    status = "blocked" if (score >= 40 or breakdown["critical"] > 0) else "passed"

    return {
        "score": score,
        "raw_score": round(raw_score, 2),
        "level": level,
        "breakdown": breakdown,
        "status": status,
    }
