from fnmatch import fnmatchcase

from app.models.domain import Principal, Statement


def _matches(patterns: list[str], value: str) -> bool:
    normalized_value = value.lower()
    return any(
        fnmatchcase(normalized_value, pattern.lower())
        for pattern in patterns
    )


def _statement_matches(
    statement: Statement,
    action: str,
    resource: str,
) -> bool:
    if statement.unsupported_elements:
        return False
    return _matches(statement.actions, action) and _matches(
        statement.resources,
        resource,
    )


def is_allowed(
    principal: Principal,
    action: str,
    resource: str,
) -> bool:
    """Return whether collected identity policies prove an action is allowed.

    CloudPathAI does not have request context for IAM Condition evaluation.
    Therefore conditional Allow statements are not treated as proof of access.
    Matching conditional Deny statements are conservatively treated as Deny.
    This avoids reporting an escalation path that depends on an unverified
    condition being satisfied.
    """
    relevant_statements = [
        statement
        for statement in principal.policies
        if _statement_matches(statement, action, resource)
    ]

    has_explicit_deny = any(
        statement.effect == "Deny"
        for statement in relevant_statements
    )
    if has_explicit_deny:
        return False

    return any(
        statement.effect == "Allow" and statement.condition is None
        for statement in relevant_statements
    )


def is_administrator(principal: Principal) -> bool:
    """Detect principals with an unconditional Allow * on Resource *."""
    return is_allowed(principal, "*", "*")
