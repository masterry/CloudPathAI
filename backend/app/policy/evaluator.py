from fnmatch import fnmatchcase

from app.models.domain import Principal


def _matches(patterns: list[str], value: str) -> bool:
    normalized_value = value.lower()

    return any(
        fnmatchcase(normalized_value, pattern.lower())
        for pattern in patterns
    )


def is_allowed(
    principal: Principal,
    action: str,
    resource: str,
) -> bool:
    relevant_statements = [
        statement
        for statement in principal.policies
        if _matches(statement.actions, action)
        and _matches(statement.resources, resource)
    ]

    has_explicit_deny = any(
        statement.effect == "Deny"
        for statement in relevant_statements
    )

    if has_explicit_deny:
        return False

    return any(
        statement.effect == "Allow"
        for statement in relevant_statements
    )


def is_administrator(principal: Principal) -> bool:
    return is_allowed(principal, "*", "*")