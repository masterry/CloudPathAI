"""AI-assisted remediation explanations.

The detection engine is the source of truth for findings, evidence, and
scores. This module only rewords that deterministic evidence into a more
readable explanation — it never invents findings or changes severity.
If no API key is configured, or the API call fails for any reason, it
falls back to a deterministic template so the app never breaks.
"""
import os

import httpx
from dotenv import load_dotenv

from app.models.domain import Finding

load_dotenv()

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
TIMEOUT_SECONDS = 8.0


def explain_finding(finding: Finding) -> str:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()

    if not api_key:
        return _fallback_explanation(finding)

    try:
        return _ai_explanation(finding, api_key)
    except (httpx.HTTPError, KeyError, ValueError, IndexError):
        # Network failure, bad response shape, rate limit, etc.
        # Never let an AI outage take down the analysis pipeline.
        return _fallback_explanation(finding)


def _ai_explanation(finding: Finding, api_key: str) -> str:
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    prompt = (
        "You are a cloud security analyst explaining an AWS IAM privilege "
        "escalation finding to an engineer who will remediate it. Use ONLY "
        "the facts given below. Do not invent AWS actions, resources, or "
        "evidence that isn't listed. Keep it to 3-4 sentences: what the "
        "risk is, why it matters, and how to fix it.\n\n"
        f"Finding: {finding.title}\n"
        f"Technique: {finding.primitive}\n"
        f"Source principal: {finding.source}\n"
        f"Target: {finding.target}\n"
        f"Severity: {finding.severity} (score {finding.score}/100)\n"
        f"Evidence:\n" + "\n".join(f"- {item}" for item in finding.evidence) + "\n"
        f"Suggested remediation: {finding.remediation}"
    )

    response = httpx.post(
        OPENAI_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 300,
        },
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def _fallback_explanation(finding: Finding) -> str:
    evidence = " ".join(finding.evidence)

    return (
        f"{finding.title}. "
        f"The attack path begins at {finding.source} and targets "
        f"{finding.target}. {evidence} "
        f"Recommended action: {finding.remediation}"
    )