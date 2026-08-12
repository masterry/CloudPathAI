from typing import Any

from app.models.domain import Statement


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def parse_policy_document(
    document: dict[str, Any],
    *,
    source_policy_arn: str | None = None,
) -> list[Statement]:
    """Parse the IAM statement subset CloudPathAI evaluates.

    Unsupported policy elements are preserved as metadata instead of being
    silently interpreted as equivalent to Action/Resource. The evaluator will
    not use such statements as positive authorization evidence.
    """
    raw_statements = document.get("Statement", [])
    if not isinstance(raw_statements, list):
        raw_statements = [raw_statements]

    parsed_statements: list[Statement] = []

    for item in raw_statements:
        if not isinstance(item, dict):
            continue

        effect = item.get("Effect")
        if effect not in {"Allow", "Deny"}:
            continue

        unsupported = [
            element
            for element in ("NotAction", "NotResource")
            if element in item
        ]

        parsed_statements.append(
            Statement(
                effect=effect,
                actions=_as_list(item.get("Action")),
                resources=_as_list(item.get("Resource")),
                condition=item.get("Condition"),
                unsupported_elements=unsupported,
                source_policy_arn=source_policy_arn,
            )
        )

    return parsed_statements
