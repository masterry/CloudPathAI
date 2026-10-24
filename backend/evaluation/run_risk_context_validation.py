
"""Test whether detected AssumeRole findings vary by authorization context.

This is a context-sensitivity test, not independent risk calibration.
"""

import csv
import json
from pathlib import Path

from app.detection.primitives import detect_primitives
from app.models.domain import Dataset, Principal, Statement

ACCOUNT = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/admin-role"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/alice"
OUTPUT = Path(__file__).resolve().parent


def run_case(name, identity_allow):
    policies = []

    if identity_allow:
        policies.append(
            Statement(
                effect="Allow",
                actions=["sts:AssumeRole"],
                resources=[ROLE_ARN],
            )
        )

    user = Principal(
        id="user:alice",
        arn=USER_ARN,
        name="alice",
        kind="User",
        policies=policies,
    )

    role = Principal(
        id="role:admin-role",
        arn=ROLE_ARN,
        name="admin-role",
        kind="Role",
        policies=[
            Statement(
                effect="Allow",
                actions=["*"],
                resources=["*"],
            )
        ],
        trust=["user:alice"],
    )

    findings = detect_primitives(
        Dataset(account_id=ACCOUNT, principals=[user, role])
    )

    matching = [
        finding for finding in findings
        if finding.primitive == "ASSUME_ADMIN_ROLE"
    ]

    if len(matching) != 1:
        raise AssertionError(
            f"{name}: expected one ASSUME_ADMIN_ROLE finding, "
            f"got {len(matching)}"
        )

    finding = matching[0]

    return {
        "scenario": name,
        "identity_policy_allow": identity_allow,
        "direct_same_account_trust": True,
        "primitive": finding.primitive,
        "score": finding.score,
        "severity": finding.severity,
    }


def main():
    rows = [
        run_case("STS-01-valid-assumption", True),
        run_case("STS-03-direct-trust-no-identity-allow", False),
    ]

    path = OUTPUT / "risk_context_results.csv"

    with path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "scenario_count": len(rows),
        "both_detected": True,
        "same_primitive": rows[0]["primitive"] == rows[1]["primitive"],
        "same_score": rows[0]["score"] == rows[1]["score"],
        "score_difference": abs(rows[0]["score"] - rows[1]["score"]),
        "interpretation": (
            "Tests whether the model differentiates authorization "
            "mechanisms within a detected primitive; equal scores "
            "do not imply incorrect risk calibration."
        ),
        "independent_expert_validation": False,
    }

    (OUTPUT / "risk_context_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    print(json.dumps(summary, indent=2))
    print(f"Saved {path.name}")
    print("Saved risk_context_summary.json")


if __name__ == "__main__":
    main()
