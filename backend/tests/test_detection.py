from app.collectors.sample_loader import load_sample
from app.detection.path_finder import build_attack_paths
from app.detection.primitives import detect_primitives
from app.models.domain import Dataset, Principal, Statement


ACCOUNT = "123456789012"


def _arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:{kind}/{name}"


def _admin_user(name: str = "admin") -> Principal:
    return Principal(
        id=f"user:{name}",
        arn=_arn("user", name),
        name=name,
        kind="User",
        policies=[Statement(effect="Allow", actions=["*"], resources=["*"])],
    )


def _admin_role(name: str = "admin-role", trust: list[str] | None = None) -> Principal:
    return Principal(
        id=f"role:{name}",
        arn=_arn("role", name),
        name=name,
        kind="Role",
        trust=trust or [],
        policies=[Statement(effect="Allow", actions=["*"], resources=["*"])],
    )


def test_sample_detects_expected_core_primitives() -> None:
    primitives = {
        finding.primitive for finding in detect_primitives(load_sample())}
    assert {
        "ASSUME_ADMIN_ROLE",
        "CREATE_ACCESS_KEY",
        "PASSROLE_LAMBDA",
        "MODIFY_OWN_ROLE",
    }.issubset(primitives)


def test_assume_role_detects_real_arn_resource() -> None:
    attacker = Principal(
        id="user:charlie",
        arn=_arn("user", "charlie"),
        name="charlie",
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=[_arn("role", "operations-admin")],
            )
        ],
    )
    target = _admin_role("operations-admin", trust=[attacker.id])

    findings = detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[attacker, target]))
    assert [f.primitive for f in findings] == ["ASSUME_ADMIN_ROLE"]
    assert findings[0].target == target.id
    assert target.arn in findings[0].evidence[0]


def test_assume_role_requires_trust() -> None:
    attacker = Principal(
        id="user:charlie",
        arn=_arn("user", "charlie"),
        name="charlie",
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=[_arn("role", "operations-admin")],
            )
        ],
    )
    target = _admin_role("operations-admin", trust=[])
    assert not detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[attacker, target]))


def test_direct_same_account_user_trust_without_identity_allow() -> None:
    """Direct same-account IAM user trust can authorize AssumeRole."""
    attacker = Principal(
        id="user:charlie",
        arn=_arn("user", "charlie"),
        name="charlie",
        kind="User",
        policies=[],
    )

    target = _admin_role(
        "operations-admin",
        trust=[attacker.id],
    )

    dataset = Dataset(
        account_id=ACCOUNT,
        principals=[attacker, target],
    )

    findings = detect_primitives(dataset)

    assert any(
        finding.primitive == "ASSUME_ADMIN_ROLE"
        and finding.source == attacker.id
        and finding.target == target.id
        for finding in findings
    )


def test_direct_same_account_trust_respects_explicit_deny() -> None:
    """An explicit Deny must block direct-trust role assumption."""
    attacker = Principal(
        id="user:charlie",
        arn=_arn("user", "charlie"),
        name="charlie",
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=[_arn("role", "operations-admin")],
            ),
            Statement(
                effect="Deny",
                actions=["sts:AssumeRole"],
                resources=[_arn("role", "operations-admin")],
            ),
        ],
    )

    target = _admin_role(
        "operations-admin",
        trust=[attacker.id],
    )

    dataset = Dataset(
        account_id=ACCOUNT,
        principals=[attacker, target],
    )

    findings = detect_primitives(dataset)

    assert not any(
        finding.primitive == "ASSUME_ADMIN_ROLE"
        and finding.source == attacker.id
        and finding.target == target.id
        for finding in findings
    )


def test_create_access_key_detects_real_user_arn() -> None:
    attacker = Principal(
        id="user:bob",
        arn=_arn("user", "bob"),
        name="bob",
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=["iam:CreateAccessKey"],
                resources=[_arn("user", "admin")],
            )
        ],
    )
    findings = detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[attacker, _admin_user()])
    )
    assert {f.primitive for f in findings} == {"CREATE_ACCESS_KEY"}


def test_explicit_deny_prevents_create_access_key_finding() -> None:
    attacker = Principal(
        id="user:bob",
        arn=_arn("user", "bob"),
        name="bob",
        kind="User",
        policies=[
            Statement(effect="Allow", actions=[
                      "iam:CreateAccessKey"], resources=["*"]),
            Statement(
                effect="Deny",
                actions=["iam:CreateAccessKey"],
                resources=[_arn("user", "admin")],
            ),
        ],
    )
    assert not detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[attacker, _admin_user()])
    )


def test_passrole_lambda_requires_lambda_trust() -> None:
    attacker = Principal(
        id="user:alice",
        arn=_arn("user", "alice"),
        name="alice",
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=["iam:PassRole", "lambda:CreateFunction",
                         "lambda:InvokeFunction"],
                resources=["*"],
            )
        ],
    )
    without_trust = _admin_role("lambda-admin", trust=[])
    with_trust = _admin_role(
        "lambda-admin-2", trust=["service:lambda.amazonaws.com"])

    findings = detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[
                attacker, without_trust, with_trust])
    )
    passrole = [f for f in findings if f.primitive == "PASSROLE_LAMBDA"]
    assert len(passrole) == 1
    assert passrole[0].target == with_trust.id


def test_modify_own_role_uses_role_arn() -> None:
    role = Principal(
        id="role:dev-role",
        arn=_arn("role", "dev-role"),
        name="dev-role",
        kind="Role",
        policies=[
            Statement(
                effect="Allow",
                actions=["iam:PutRolePolicy"],
                resources=[_arn("role", "dev-role")],
            )
        ],
    )
    findings = detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[role]))
    assert {f.primitive for f in findings} == {"MODIFY_OWN_ROLE"}


def test_create_policy_version_requires_policy_attached_to_caller() -> None:
    attached = "arn:aws:iam::123456789012:policy/DeveloperPolicy"
    unrelated = "arn:aws:iam::123456789012:policy/UnrelatedPolicy"
    principal = Principal(
        id="user:policy-editor",
        arn=_arn("user", "policy-editor"),
        name="policy-editor",
        kind="User",
        attached_managed_policy_arns=[attached],
        policies=[
            Statement(
                effect="Allow",
                actions=["iam:CreatePolicyVersion"],
                resources=[unrelated],
            )
        ],
    )
    assert not detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[principal]))

    principal.policies.append(
        Statement(
            effect="Allow",
            actions=["iam:CreatePolicyVersion"],
            resources=[attached],
        )
    )
    findings = detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[principal]))
    assert {f.primitive for f in findings} == {"CREATE_POLICY_VERSION"}


def test_update_trust_policy_wording_is_conservative() -> None:
    attacker = Principal(
        id="user:trust-editor",
        arn=_arn("user", "trust-editor"),
        name="trust-editor",
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=["iam:UpdateAssumeRolePolicy"],
                resources=[_arn("role", "admin-role")],
            )
        ],
    )
    target = _admin_role("admin-role")
    findings = detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[attacker, target]))
    finding = next(f for f in findings if f.primitive ==
                   "UPDATE_ASSUME_ROLE_POLICY")
    assert "prerequisite" in " ".join(finding.evidence).lower()


def test_scores_are_bounded_and_paths_are_generated() -> None:
    findings = detect_primitives(load_sample())
    assert all(0 <= finding.score <= 100 for finding in findings)
    assert build_attack_paths(findings)


def test_conditional_assume_role_allow_does_not_produce_finding() -> None:
    """Unverified conditional authorization must not create a risk finding."""
    attacker = Principal(
        id="role:developer",
        arn=_arn("role", "developer"),
        name="developer",
        kind="Role",
        policies=[
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=[_arn("role", "operations-admin")],
                condition={
                    "Bool": {
                        "aws:MultiFactorAuthPresent": "true"
                    }
                },
            )
        ],
    )

    target = _admin_role(
        "operations-admin",
        trust=[attacker.id],
    )

    findings = detect_primitives(
        Dataset(
            account_id=ACCOUNT,
            principals=[attacker, target],
        )
    )

    assert not any(
        finding.primitive == "ASSUME_ADMIN_ROLE"
        for finding in findings
    )
