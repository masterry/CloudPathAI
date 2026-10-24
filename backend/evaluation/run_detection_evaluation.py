
import csv
import json
from pathlib import Path

from app.detection.primitives import detect_primitives
from app.models.domain import Dataset, Principal, Statement

ACCOUNT = "123456789012"
OUTPUT = Path(__file__).resolve().parent


def arn(kind, name):
    return f"arn:aws:iam::{ACCOUNT}:{kind}/{name}"


def principal(name, kind="User", actions=None, resources=None,
              trust=None, admin=False, attached=None):
    policies = (
        [Statement(effect="Allow", actions=["*"], resources=["*"])]
        if admin
        else [
            Statement(
                effect="Allow",
                actions=actions or [],
                resources=resources or ["*"],
            )
        ] if actions else []
    )
    return Principal(
        id=f"{kind.lower()}:{name}",
        arn=arn(kind.lower(), name),
        name=name,
        kind=kind,
        policies=policies,
        trust=trust or [],
        attached_managed_policy_arns=attached or [],
    )


def scenario(name, principals, expected):
    return {
        "scenario": name,
        "dataset": Dataset(account_id=ACCOUNT, principals=principals),
        "expected": expected,
    }


admin_role = principal("admin-role", kind="Role", admin=True)
admin_user = principal("admin-user", admin=True)
lambda_admin = principal(
    "lambda-admin",
    kind="Role",
    admin=True,
    trust=["service:lambda.amazonaws.com"],
)
managed_policy = arn("policy", "DeveloperPolicy")

scenarios = [
    scenario(
        "S01_assume_admin_allowed",
        [
            principal(
                "alice",
                actions=["sts:AssumeRole"],
                resources=[admin_role.arn],
            ),
            principal(
                "admin-role", kind="Role", admin=True,
                trust=["user:alice"],
            ),
        ],
        "ASSUME_ADMIN_ROLE",
    ),
    scenario(
        "S02_assume_admin_no_trust",
        [
            principal(
                "alice",
                actions=["sts:AssumeRole"],
                resources=[admin_role.arn],
            ),
            admin_role,
        ],
        None,
    ),
    scenario(
        "S03_create_admin_access_key",
        [
            principal(
                "bob",
                actions=["iam:CreateAccessKey"],
                resources=[admin_user.arn],
            ),
            admin_user,
        ],
        "CREATE_ACCESS_KEY",
    ),
    scenario(
        "S04_create_access_key_wrong_resource",
        [
            principal(
                "bob",
                actions=["iam:CreateAccessKey"],
                resources=[arn("user", "someone-else")],
            ),
            admin_user,
        ],
        None,
    ),
    scenario(
        "S05_passrole_lambda",
        [
            principal(
                "alice",
                actions=[
                    "iam:PassRole",
                    "lambda:CreateFunction",
                    "lambda:InvokeFunction",
                ],
            ),
            lambda_admin,
        ],
        "PASSROLE_LAMBDA",
    ),
    scenario(
        "S06_passrole_missing_invoke",
        [
            principal(
                "alice",
                actions=["iam:PassRole", "lambda:CreateFunction"],
            ),
            lambda_admin,
        ],
        None,
    ),
    scenario(
        "S07_modify_own_role",
        [
            principal(
                "dev",
                kind="Role",
                actions=["iam:PutRolePolicy"],
                resources=[arn("role", "dev")],
            )
        ],
        "MODIFY_OWN_ROLE",
    ),
    scenario(
        "S08_modify_other_role_only",
        [
            principal(
                "dev",
                kind="Role",
                actions=["iam:PutRolePolicy"],
                resources=[arn("role", "other")],
            )
        ],
        None,
    ),
    scenario(
        "S09_create_attached_policy_version",
        [
            principal(
                "editor",
                actions=["iam:CreatePolicyVersion"],
                resources=[managed_policy],
                attached=[managed_policy],
            )
        ],
        "CREATE_POLICY_VERSION",
    ),
    scenario(
        "S10_create_unattached_policy_version",
        [
            principal(
                "editor",
                actions=["iam:CreatePolicyVersion"],
                resources=[managed_policy],
            )
        ],
        None,
    ),
    scenario(
        "S11_attach_own_user_policy",
        [
            principal(
                "alice",
                actions=["iam:AttachUserPolicy"],
                resources=[arn("user", "alice")],
            )
        ],
        "ATTACH_USER_POLICY",
    ),
    scenario(
        "S12_attach_other_user_policy_only",
        [
            principal(
                "alice",
                actions=["iam:AttachUserPolicy"],
                resources=[arn("user", "bob")],
            )
        ],
        None,
    ),
    scenario(
        "S13_update_admin_trust",
        [
            principal(
                "alice",
                actions=["iam:UpdateAssumeRolePolicy"],
                resources=[admin_role.arn],
            ),
            admin_role,
        ],
        "UPDATE_ASSUME_ROLE_POLICY",
    ),
    scenario(
        "S14_update_nonadmin_trust",
        [
            principal(
                "alice",
                actions=["iam:UpdateAssumeRolePolicy"],
                resources=[arn("role", "ordinary")],
            ),
            principal("ordinary", kind="Role"),
        ],
        None,
    ),
]


risk_rows = []

for item in scenarios:
    findings = detect_primitives(item["dataset"])

    for finding in findings:
        risk_rows.append({
            "scenario": item["scenario"],
            "finding_id": finding.id,
            "primitive": finding.primitive,
            "source": finding.source,
            "target": finding.target,
            "cloudpath_score": finding.score,
            "severity": finding.severity,
            "expert_1_score": "",
            "expert_2_score": "",
        })

with (OUTPUT / "risk_validation_template.csv").open(
    "w", newline=""
) as file:
    fieldnames = [
        "scenario",
        "finding_id",
        "primitive",
        "source",
        "target",
        "cloudpath_score",
        "severity",
        "expert_1_score",
        "expert_2_score",
    ]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(risk_rows)

print(f"Exported {len(risk_rows)} findings for risk review")


rows = []
tp = fp = tn = fn = 0

for item in scenarios:
    findings = detect_primitives(item["dataset"])
    detected = {f.primitive for f in findings}

    expected = item["expected"]
    predicted = expected in detected if expected else bool(detected)
    actual = expected is not None

    if actual and predicted:
        outcome = "TP"
        tp += 1
    elif actual and not predicted:
        outcome = "FN"
        fn += 1
    elif not actual and predicted:
        outcome = "FP"
        fp += 1
    else:
        outcome = "TN"
        tn += 1

    rows.append({
        "scenario": item["scenario"],
        "expected_primitive": expected or "NONE",
        "detected_primitives": ";".join(sorted(detected)) or "NONE",
        "outcome": outcome,
    })

with (OUTPUT / "detection_results.csv").open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

precision = tp / (tp + fp) if tp + fp else None
recall = tp / (tp + fn) if tp + fn else None
fnr = fn / (tp + fn) if tp + fn else None

summary = {
    "scenario_count": len(rows),
    "true_positives": tp,
    "false_positives": fp,
    "true_negatives": tn,
    "false_negatives": fn,
    "precision": precision,
    "recall": recall,
    "false_negative_rate": fnr,
}

(OUTPUT / "evaluation_summary.json").write_text(
    json.dumps(summary, indent=2)
)

print(json.dumps(summary, indent=2))
print("\nSaved evaluation/detection_results.csv")
print("Saved evaluation/evaluation_summary.json")


# Export detailed scenarios for independent risk review.
review_rows = []

for item in scenarios:
    findings = detect_primitives(item["dataset"])

    for finding in findings:
        principals = [
            principal.model_dump(mode="json")
            for principal in item["dataset"].principals
        ]

        review_rows.append({
            "scenario": item["scenario"],
            "primitive": finding.primitive,
            "description": finding.title,
            "source": finding.source,
            "target": finding.target,
            "iam_configuration": json.dumps(principals),
            "evidence": " | ".join(finding.evidence),
            "reviewer_score": "",
            "reviewer_notes": "",
        })

review_fields = [
    "scenario",
    "primitive",
    "description",
    "source",
    "target",
    "iam_configuration",
    "evidence",
    "reviewer_score",
    "reviewer_notes",
]

with (OUTPUT / "risk_review_detailed.csv").open(
    "w", newline=""
) as file:
    writer = csv.DictWriter(file, fieldnames=review_fields)
    writer.writeheader()
    writer.writerows(review_rows)

print(f"Exported {len(review_rows)} detailed risk scenarios")
