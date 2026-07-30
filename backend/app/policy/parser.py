from typing import Any

from app.models.domain import Statement


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def parse_policy_document(document: dict[str, Any]) -> list[Statement]:
    raw_statements = document.get("Statement", [])

    if not isinstance(raw_statements, list):
        raw_statements = [raw_statements]

    parsed_statements: list[Statement] = []

    for item in raw_statements:
        effect = item.get("Effect")

        if effect not in {"Allow", "Deny"}:
            continue

        parsed_statements.append(
            Statement(
                effect=effect,
                actions=_as_list(item.get("Action")),
                resources=_as_list(item.get("Resource")),
                condition=item.get("Condition"),
            )
        )

    return parsed_statements