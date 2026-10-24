
from app.models.domain import Dataset, Principal, Statement
from app.detection.primitives import detect_primitives

ACCOUNT = "123456789012"


def arn(kind, name):
    return f"arn:aws:iam::{ACCOUNT}:{kind}/{name}"


def admin_user(name):
    return Principal(
        id=f"user:{name}",
        arn=arn("user", name),
        name=name,
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=["*"],
                resources=["*"],
            )
        ],
    )


def attacker_with_permission(action, target_arn):
    return Principal(
        id="user:attacker",
        arn=arn("user", "attacker"),
        name="attacker",
        kind="User",
        policies=[
            Statement(
                effect="Allow",
                actions=[action],
                resources=[target_arn],
            )
        ],
    )


cases = [
    {
        "name": "CreateLoginProfile on admin user",
        "action": "iam:CreateLoginProfile",
        "target": arn("user", "admin"),
        "ground_truth_status": "conditional",
    },
    {
        "name": "UpdateLoginProfile on admin user",
        "action": "iam:UpdateLoginProfile",
        "target": arn("user", "admin"),
        "ground_truth_status": "conditional",
    },
]

for case in cases:
    dataset = Dataset(
        account_id=ACCOUNT,
        principals=[
            attacker_with_permission(
                case["action"],
                case["target"],
            ),
            admin_user("admin"),
        ],
    )

    findings = detect_primitives(dataset)

    print(f"\nScenario: {case['name']}")
    print("Ground-truth status:", case["ground_truth_status"])
    print("Findings:", len(findings))
    print("Primitives:", [f.primitive for f in findings])
