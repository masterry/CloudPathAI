from app.detection.risk_scoring import RiskFactors, calculate_score, severity_for
from app.models.domain import Dataset, Finding, Principal
from app.policy.evaluator import is_administrator, is_allowed


def _has_explicit_deny(
    principal: Principal,
    action: str,
    resource: str,
) -> bool:
    """Check supported identity-policy statements for an applicable Deny."""
    from app.policy.evaluator import _statement_matches

    return any(
        statement.effect == "Deny"
        and _statement_matches(statement, action, resource)
        for statement in principal.policies
    )


def _finding(
    *,
    finding_id: str,
    primitive: str,
    title: str,
    source: str,
    target: str,
    risk_factors: RiskFactors,
    evidence: list[str],
    remediation: str,
) -> Finding:
    score = calculate_score(risk_factors)
    return Finding(
        id=finding_id,
        primitive=primitive,
        title=title,
        source=source,
        target=target,
        severity=severity_for(score),
        score=score,
        evidence=evidence,
        remediation=remediation,
    )


def _detect_assume_admin_role(
    dataset: Dataset,
    principal: Principal,
) -> list[Finding]:
    if is_administrator(principal):
        return []

    findings: list[Finding] = []
    for target in dataset.principals:
        if target.kind != "Role" or not is_administrator(target):
            continue
        if principal.id not in target.trust:
            continue

        identity_allowed = is_allowed(
            principal, "sts:AssumeRole", target.resource
        )

        direct_same_account_user_trust = (
            principal.kind == "User"
            and principal.arn.startswith(
                f"arn:aws:iam::{dataset.account_id}:user/"
            )
            and principal.id in target.trust
        )

        if _has_explicit_deny(
            principal, "sts:AssumeRole", target.resource
        ):
            continue

        if not (identity_allowed or direct_same_account_user_trust):
            continue

        findings.append(
            _finding(
                finding_id=f"assume-admin-role:{principal.id}:{target.id}",
                primitive="ASSUME_ADMIN_ROLE",
                title="Principal can assume an administrator role",
                source=principal.id,
                target=target.id,
                risk_factors=RiskFactors(
                    impact=100, exploitability=90, confidence=95),
                evidence=[
                    f"{principal.id} can assume {target.resource} through identity permissions or direct same-account trust",
                    f"{target.id} trusts {principal.id}",
                    f"{target.id} has unconditional administrator-level permissions",
                ],
                remediation=(
                    "Restrict sts:AssumeRole permissions and remove unnecessary "
                    "principals from the privileged role trust policy."
                ),
            )
        )

    return findings


def _detect_create_access_key(
    dataset: Dataset,
    principal: Principal,
) -> list[Finding]:
    if is_administrator(principal):
        return []

    findings: list[Finding] = []
    for target in dataset.principals:
        if target.kind != "User" or not is_administrator(target):
            continue
        if principal.id == target.id:
            continue
        if not is_allowed(principal, "iam:CreateAccessKey", target.resource):
            continue

        findings.append(
            _finding(
                finding_id=f"create-access-key:{principal.id}:{target.id}",
                primitive="CREATE_ACCESS_KEY",
                title="Principal can create keys for an administrator user",
                source=principal.id,
                target=target.id,
                risk_factors=RiskFactors(
                    impact=100, exploitability=90, confidence=95),
                evidence=[
                    f"{principal.id} is allowed iam:CreateAccessKey on {target.resource}",
                    f"{target.id} has unconditional administrator-level permissions",
                ],
                remediation=(
                    "Remove iam:CreateAccessKey access to privileged users and "
                    "rotate any credentials created outside the approved process."
                ),
            )
        )

    return findings


def _detect_passrole_lambda(
    dataset: Dataset,
    principal: Principal,
) -> list[Finding]:
    if is_administrator(principal):
        return []

    # Without a concrete function ARN/request context, Resource "*" is the
    # only authorization this analyzer can prove for these Lambda operations.
    if not is_allowed(principal, "lambda:CreateFunction", "*"):
        return []
    if not is_allowed(principal, "lambda:InvokeFunction", "*"):
        return []

    findings: list[Finding] = []
    for target in dataset.principals:
        if target.kind != "Role" or not is_administrator(target):
            continue
        if "service:lambda.amazonaws.com" not in target.trust:
            continue
        if not is_allowed(principal, "iam:PassRole", target.resource):
            continue

        findings.append(
            _finding(
                finding_id=f"passrole-lambda:{principal.id}:{target.id}",
                primitive="PASSROLE_LAMBDA",
                title="Principal can pass an administrator role to Lambda",
                source=principal.id,
                target=target.id,
                risk_factors=RiskFactors(
                    impact=100, exploitability=90, confidence=95),
                evidence=[
                    f"{principal.id} is allowed iam:PassRole on {target.resource}",
                    f"{principal.id} has unconditional Lambda create/invoke permissions on *",
                    f"{target.id} trusts the Lambda service",
                    f"{target.id} has unconditional administrator-level permissions",
                ],
                remediation=(
                    "Restrict iam:PassRole to approved execution roles and limit "
                    "Lambda creation and invocation permissions."
                ),
            )
        )

    return findings


def _detect_role_policy_escalation(principal: Principal) -> list[Finding]:
    if principal.kind != "Role" or is_administrator(principal):
        return []

    dangerous_actions = ("iam:AttachRolePolicy", "iam:PutRolePolicy")
    matched_actions = [
        action
        for action in dangerous_actions
        if is_allowed(principal, action, principal.resource)
    ]
    if not matched_actions:
        return []

    return [
        _finding(
            finding_id=f"modify-own-role:{principal.id}",
            primitive="MODIFY_OWN_ROLE",
            title="Role can modify its own permissions",
            source=principal.id,
            target=principal.id,
            risk_factors=RiskFactors(
                impact=90, exploitability=75, confidence=90),
            evidence=[
                f"{principal.id} is allowed {action} on {principal.resource}"
                for action in matched_actions
            ],
            remediation=(
                "Remove self-modification permissions and require a separate, "
                "controlled IAM administration role for permission changes."
            ),
        )
    ]


def _detect_create_policy_version(principal: Principal) -> list[Finding]:
    """Detect modification of a managed policy that currently affects principal.

    This deliberately avoids the previous broad claim that CreatePolicyVersion
    on any policy necessarily escalates the caller. A finding is emitted only
    when the caller can create a version of a managed policy collected as
    attached to that caller (directly or, for users, through group membership).
    """
    if is_administrator(principal):
        return []

    modifiable_policies = [
        policy_arn
        for policy_arn in principal.attached_managed_policy_arns
        if is_allowed(principal, "iam:CreatePolicyVersion", policy_arn)
    ]
    if not modifiable_policies:
        return []

    return [
        _finding(
            finding_id=f"create-policy-version:{principal.id}",
            primitive="CREATE_POLICY_VERSION",
            title="Principal can version a managed policy that grants its permissions",
            source=principal.id,
            target=principal.id,
            risk_factors=RiskFactors(
                impact=95, exploitability=80, confidence=90),
            evidence=[
                f"{principal.id} is allowed iam:CreatePolicyVersion on {policy_arn}"
                for policy_arn in modifiable_policies
            ] + [
                "The affected managed policy is attached to the principal or one of its groups"
            ],
            remediation=(
                "Restrict iam:CreatePolicyVersion on policies that affect the caller "
                "and reserve managed-policy version changes for a controlled IAM role."
            ),
        )
    ]


def _detect_attach_user_policy(principal: Principal) -> list[Finding]:
    if principal.kind != "User" or is_administrator(principal):
        return []
    if not is_allowed(principal, "iam:AttachUserPolicy", principal.resource):
        return []

    return [
        _finding(
            finding_id=f"attach-user-policy:{principal.id}",
            primitive="ATTACH_USER_POLICY",
            title="User can attach a managed policy to itself",
            source=principal.id,
            target=principal.id,
            risk_factors=RiskFactors(
                impact=95, exploitability=85, confidence=85),
            evidence=[
                f"{principal.id} is allowed iam:AttachUserPolicy on {principal.resource}",
                "This permission can enable self-escalation unless policy selection is constrained",
            ],
            remediation=(
                "Remove self-service IAM policy attachment permissions and use an "
                "approval-controlled provisioning role. Review any iam:PolicyARN conditions."
            ),
        )
    ]


def _detect_update_trust_policy(
    dataset: Dataset,
    principal: Principal,
) -> list[Finding]:
    """Detect a dangerous prerequisite: rewriting a privileged role trust policy."""
    if is_administrator(principal):
        return []

    findings: list[Finding] = []
    for target in dataset.principals:
        if target.kind != "Role" or not is_administrator(target):
            continue
        if not is_allowed(principal, "iam:UpdateAssumeRolePolicy", target.resource):
            continue

        findings.append(
            _finding(
                finding_id=f"update-trust-policy:{principal.id}:{target.id}",
                primitive="UPDATE_ASSUME_ROLE_POLICY",
                title="Principal can weaken an administrator role trust policy",
                source=principal.id,
                target=target.id,
                risk_factors=RiskFactors(
                    impact=100, exploitability=70, confidence=85),
                evidence=[
                    f"{principal.id} is allowed iam:UpdateAssumeRolePolicy on {target.resource}",
                    f"{target.id} has unconditional administrator-level permissions",
                    "Changing trust is a privilege-escalation prerequisite; it does not alone prove successful role assumption",
                ],
                remediation=(
                    "Restrict iam:UpdateAssumeRolePolicy on privileged roles and "
                    "monitor trust-policy changes with CloudTrail."
                ),
            )
        )

    return findings


def detect_primitives(dataset: Dataset) -> list[Finding]:
    findings: list[Finding] = []

    for principal in dataset.principals:
        findings.extend(_detect_assume_admin_role(dataset, principal))
        findings.extend(_detect_create_access_key(dataset, principal))
        findings.extend(_detect_passrole_lambda(dataset, principal))
        findings.extend(_detect_role_policy_escalation(principal))
        findings.extend(_detect_create_policy_version(principal))
        findings.extend(_detect_attach_user_policy(principal))
        findings.extend(_detect_update_trust_policy(dataset, principal))

    return findings
