import os

from dotenv import load_dotenv

from app.models.domain import Finding


load_dotenv()


def explain_finding(finding: Finding) -> str:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()

    if not api_key:
        return _fallback_explanation(finding)

    # AI integration can be added after the core MVP is running.
    return _fallback_explanation(finding)


def _fallback_explanation(finding: Finding) -> str:
    evidence = " ".join(finding.evidence)

    return (
        f"{finding.title}. "
        f"The attack path begins at {finding.source} and targets "
        f"{finding.target}. {evidence} "
        f"Recommended action: {finding.remediation}"
    )