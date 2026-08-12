import os

from app.ai.explainer import explain_finding
from app.models.domain import Finding


def _sample_finding() -> Finding:
    return Finding(
        id="test:1",
        primitive="ASSUME_ADMIN_ROLE",
        title="Principal can assume an administrator role",
        source="user:alice",
        target="role:admin",
        severity="critical",
        score=95,
        evidence=["user:alice can call sts:AssumeRole on role:admin"],
        remediation="Restrict sts:AssumeRole permissions.",
    )


def test_fallback_used_when_no_api_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    text = explain_finding(_sample_finding())

    assert "assume an administrator role" in text.lower()
    assert "user:alice" in text
    assert "role:admin" in text
    assert "Restrict sts:AssumeRole" in text


def test_fallback_never_raises_with_bad_key(monkeypatch) -> None:
    # An invalid/expired key should degrade gracefully, not crash the pipeline
    monkeypatch.setenv("OPENAI_API_KEY", "sk-invalid-test-key")
    text = explain_finding(_sample_finding())

    assert isinstance(text, str)
    assert len(text) > 0