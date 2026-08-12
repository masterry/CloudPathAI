from dataclasses import dataclass


@dataclass(frozen=True)
class RiskFactors:
    """Transparent factors used to calculate a deterministic 0-100 score."""

    impact: int
    exploitability: int
    confidence: int


def calculate_score(factors: RiskFactors) -> int:
    """Calculate a reproducible finding score.

    The score describes a finding itself. Path aggregation is handled by the
    path layer and does not silently alter the finding's original risk model.
    """
    for value in (factors.impact, factors.exploitability, factors.confidence):
        if not 0 <= value <= 100:
            raise ValueError("Risk factors must be between 0 and 100")

    base = (
        0.50 * factors.impact
        + 0.30 * factors.exploitability
        + 0.20 * factors.confidence
    )
    return round(min(100, base))


def severity_for(score: int) -> str:
    if not 0 <= score <= 100:
        raise ValueError("Score must be between 0 and 100")
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def score_for(severity: str) -> int:
    """Backward-compatible helper for existing callers."""
    defaults = {
        "low": RiskFactors(impact=30, exploitability=35, confidence=80),
        "medium": RiskFactors(impact=55, exploitability=55, confidence=85),
        "high": RiskFactors(impact=80, exploitability=75, confidence=90),
        "critical": RiskFactors(impact=100, exploitability=95, confidence=95),
    }
    factors = defaults.get(severity)
    return calculate_score(factors) if factors else 0
