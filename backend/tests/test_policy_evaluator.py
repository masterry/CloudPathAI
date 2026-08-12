from app.models.domain import Principal, Statement
from app.policy.evaluator import is_allowed


ROLE_ARN = "arn:aws:iam::123456789012:role/operations-admin"
USER_ARN = "arn:aws:iam::123456789012:user/admin-user"


def _principal(*statements: Statement) -> Principal:
    return Principal(
        id="user:test",
        arn="arn:aws:iam::123456789012:user/test",
        name="test",
        kind="User",
        policies=list(statements),
    )


def test_explicit_deny_overrides_allow() -> None:
    principal = _principal(
        Statement(effect="Allow", actions=["iam:*"], resources=["*"]),
        Statement(effect="Deny", actions=["iam:CreateAccessKey"], resources=[USER_ARN]),
    )
    assert not is_allowed(principal, "iam:CreateAccessKey", USER_ARN)


def test_exact_arn_resource_matches() -> None:
    principal = _principal(
        Statement(effect="Allow", actions=["sts:AssumeRole"], resources=[ROLE_ARN])
    )
    assert is_allowed(principal, "sts:AssumeRole", ROLE_ARN)


def test_arn_resource_wildcard_matches() -> None:
    principal = _principal(
        Statement(
            effect="Allow",
            actions=["sts:*"],
            resources=["arn:aws:iam::123456789012:role/operations-*"],
        )
    )
    assert is_allowed(principal, "sts:AssumeRole", ROLE_ARN)


def test_wrong_arn_resource_does_not_match() -> None:
    principal = _principal(
        Statement(
            effect="Allow",
            actions=["sts:AssumeRole"],
            resources=["arn:aws:iam::123456789012:role/dev-*"],
        )
    )
    assert not is_allowed(principal, "sts:AssumeRole", ROLE_ARN)


def test_conditional_allow_is_not_treated_as_proven_access() -> None:
    principal = _principal(
        Statement(
            effect="Allow",
            actions=["sts:AssumeRole"],
            resources=[ROLE_ARN],
            condition={"StringEquals": {"aws:PrincipalTag/team": "security"}},
        )
    )
    assert not is_allowed(principal, "sts:AssumeRole", ROLE_ARN)


def test_unsupported_notaction_statement_is_not_used_as_allow() -> None:
    principal = _principal(
        Statement(
            effect="Allow",
            actions=[],
            resources=["*"],
            unsupported_elements=["NotAction"],
        )
    )
    assert not is_allowed(principal, "iam:CreateAccessKey", USER_ARN)
