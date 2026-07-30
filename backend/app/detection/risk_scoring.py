SEVERITY_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


def score_for(severity: str) -> int:
    return SEVERITY_SCORES.get(severity, 0)