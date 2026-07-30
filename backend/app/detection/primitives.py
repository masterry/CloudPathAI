from app.detection.risk_scoring import score_for
from app.models.domain import Dataset, Finding, Principal
from app.policy.evaluator import is_administrator, is_allowed


def _finding(
    *,
    finding_id: str,
    primitive: str,
    title: str,
    source: str,
    target: str,
    severity: str,
    evidence: list[str],
    remediation: str,
) -> Finding:
    return Finding(
        id=finding_id,
        primitive=primitive,
        title=title,
        source=source,
        target=target,
        severity=severity,
        score=score_for(severity),
        evidence=evidence,
        remediation=remediation,
    )


def _detect_assume_admin_role(
    dataset: Dataset,
    principal: Principal,
) -> list[Finding]:
    findings: list[Finding] = []

    # Already-admin principals have no privilege escalation to detect.
    if is_administrator(principal):
        return findings

    for target in dataset.principals:
        if target.kind != "Role":
            continue

        if not is_administrator(target):
            continue

        # Both identity permission and role trust are required.
        if principal.id not in target.trust:
            continue

        if is_allowed(principal, "sts:AssumeRole", target.id):
            findings.append(
                _finding(
                    finding_id=f"assume-admin-role:{principal.id}:{target.id}",
                    primitive="ASSUME_ADMIN_ROLE",
                    title="Principal can assume an administrator role",
                    source=principal.id,
                    target=target.id,
                    severity="critical",
                    evidence=[
                        f"{principal.id} can call sts:AssumeRole on {target.id}",
                        f"{target.id} trusts {principal.id}",
                        f"{target.id} has administrator-level permissions",
                    ],
                    remediation=(
                        "Restrict sts:AssumeRole permissions and remove "
                        "unnecessary principals from the role trust policy."
                    ),
                )
            )

    return findings


def _detect_create_access_key(
    dataset: Dataset,
    principal: Principal,
) -> list[Finding]:
    findings: list[Finding] = []

    if is_administrator(principal):
        return findings

    for target in dataset.principals:
        if target.kind != "User":
            continue

        if not is_administrator(target):
            continue

        if principal.id == target.id:
            continue

        if is_allowed(principal, "iam:CreateAccessKey", target.id):
            findings.append(
                _finding(
                    finding_id=f"create-access-key:{principal.id}:{target.id}",
                    primitive="CREATE_ACCESS_KEY",
                    title="Principal can create keys for an administrator user",
                    source=principal.id,
                    target=target.id,
                    severity="critical",
                    evidence=[
                        f"{principal.id} can call iam:CreateAccessKey on {target.id}",
                        f"{target.id} has administrator-level permissions",
                    ],
                    remediation=(
                        "Remove iam:CreateAccessKey access to privileged users "
                        "and rotate any exposed credentials."
                    ),
                )
            )

    return findings


def _detect_passrole_lambda(
    dataset: Dataset,
    principal: Principal,
) -> list[Finding]:
    findings: list[Finding] = []

    if is_administrator(principal):
        return findings

    can_create_function = is_allowed(
        principal,
        "lambda:CreateFunction",
        "*",
    )
    can_invoke_function = is_allowed(
        principal,
        "lambda:InvokeFunction",
        "*",
    )

    if not can_create_function or not can_invoke_function:
        return findings

    for target in dataset.principals:
        if target.kind != "Role":
            continue

        if not is_administrator(target):
            continue

        # Lambda must be allowed to assume the passed role.
        if "service:lambda.amazonaws.com" not in target.trust:
            continue

        if is_allowed(principal, "iam:PassRole", target.id):
            findings.append(
                _finding(
                    finding_id=f"passrole-lambda:{principal.id}:{target.id}",
                    primitive="PASSROLE_LAMBDA",
                    title="Principal can pass an administrator role to Lambda",
                    source=principal.id,
                    target=target.id,
                    severity="critical",
                    evidence=[
                        f"{principal.id} can call iam:PassRole on {target.id}",
                        f"{principal.id} can create and invoke Lambda functions",
                        f"{target.id} trusts the Lambda service",
                        f"{target.id} has administrator-level permissions",
                    ],
                    remediation=(
                        "Restrict iam:PassRole to approved roles and limit "
                        "Lambda creation and invocation permissions."
                    ),
                )
            )

    return findings


def _detect_role_policy_escalation(
    principal: Principal,
) -> list[Finding]:
    findings: list[Finding] = []

    if principal.kind != "Role":
        return findings

    if is_administrator(principal):
        return findings

    dangerous_actions = [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
    ]

    matched_actions = [
        action
        for action in dangerous_actions
        if is_allowed(principal, action, principal.id)
    ]

    if matched_actions:
        findings.append(
            _finding(
                finding_id=f"modify-own-role:{principal.id}",
                primitive="MODIFY_OWN_ROLE",
                title="Role can modify its own permissions",
                source=principal.id,
                target=principal.id,
                severity="high",
                evidence=[
                    f"{principal.id} can call {action} on itself"
                    for action in matched_actions
                ],
                remediation=(
                    "Remove self-modification permissions and require a "
                    "separate controlled deployment role for IAM changes."
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

    return findings