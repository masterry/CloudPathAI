import pytest

from app.detection.risk_scoring import RiskFactors, calculate_score, severity_for


def test_score_is_reproducible() -> None:
    score = calculate_score(RiskFactors(impact=100, exploitability=90, confidence=95))
    assert score == 96
    assert severity_for(score) == "critical"


def test_severity_boundaries() -> None:
    assert severity_for(39) == "low"
    assert severity_for(40) == "medium"
    assert severity_for(69) == "medium"
    assert severity_for(70) == "high"
    assert severity_for(89) == "high"
    assert severity_for(90) == "critical"


def test_invalid_factor_is_rejected() -> None:
    with pytest.raises(ValueError):
        calculate_score(RiskFactors(impact=101, exploitability=50, confidence=50))


def test_invalid_score_is_rejected() -> None:
    with pytest.raises(ValueError):
        severity_for(101)
