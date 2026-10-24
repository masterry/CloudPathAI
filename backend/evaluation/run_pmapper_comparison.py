
"""Reproducible offline STS comparison: CloudPathAI vs PMapper 1.1.5."""

import csv
import json
from pathlib import Path

import evaluation.pmapper_compat

import principalmapper
from principalmapper.common.graphs import Graph
from principalmapper.common.nodes import Node
from principalmapper.common.policies import Policy
from principalmapper.graphing.sts_edges import STSEdgeChecker
from principalmapper.querying.presets.privesc import can_privesc

from app.detection.primitives import detect_primitives
from app.models.domain import Dataset, Principal, Statement


ACCOUNT = "123456789012"
OUTPUT = Path(__file__).resolve().parent
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/alice"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/admin-role"


def pmapper_node(arn, identifier, policies, trust, admin):
    return Node(
        arn=arn,
        id_value=identifier,
        attached_policies=policies,
        group_memberships=[],
        trust_policy=trust,
        instance_profile=None,
        num_access_keys=0,
        active_password=False,
        is_admin=admin,
        permissions_boundary=None,
        has_mfa=False,
        tags={},
    )


def run_pmapper(trusted, allow_assume=True, explicit_deny=False):
    policy = Policy(
        arn=f"arn:aws:iam::{ACCOUNT}:policy/AssumeRolePolicy",
        name="AssumeRolePolicy",

        policy_doc={
            "Version": "2012-10-17",
            "Statement": (
                [{
                    "Effect": "Allow",
                    "Action": (
                        "sts:AssumeRole"
                        if allow_assume
                        else "s3:ListBucket"
                    ),
                    "Resource": ROLE_ARN,
                }]
                + (
                    [{
                        "Effect": "Deny",
                        "Action": "sts:AssumeRole",
                        "Resource": ROLE_ARN,
                    }]
                    if explicit_deny
                    else []
                )
            ),
        },

    )

    user = pmapper_node(
        USER_ARN, "AIDAEXAMPLE001", [policy], None, False
    )

    trusted_arn = (
        USER_ARN
        if trusted
        else f"arn:aws:iam::{ACCOUNT}:role/unrelated-role"
    )

    role = pmapper_node(
        ROLE_ARN,
        "AROAEXAMPLE001",
        [],
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": trusted_arn},
                "Action": "sts:AssumeRole",
            }],
        },
        True,
    )

    edges = STSEdgeChecker(None).return_edges([user, role])

    graph = Graph(
        nodes=[user, role],
        edges=edges,
        policies=[policy],
        groups=[],
        metadata={
            "account_id": ACCOUNT,
            "pmapper_version": principalmapper.__version__,
        },
    )

    detected, path = can_privesc(graph, user)
    return bool(detected), len(edges), len(path) if path else 0


def run_cloudpath(trusted, allow_assume=True, explicit_deny=False):
    user = Principal(
        id="user:alice",
        arn=USER_ARN,
        name="alice",
        kind="User",

        policies=(
            (
                [
                    Statement(
                        effect="Allow",
                        actions=["sts:AssumeRole"],
                        resources=[ROLE_ARN],
                    )
                ]
                if allow_assume
                else []
            )
            +
            (
                [
                    Statement(
                        effect="Deny",
                        actions=["sts:AssumeRole"],
                        resources=[ROLE_ARN],
                    )
                ]
                if explicit_deny
                else []
            )
        ),

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
        trust=["user:alice"] if trusted else [],
        attached_managed_policy_arns=[],
    )

    dataset = Dataset(
        account_id=ACCOUNT,
        principals=[user, role],
    )

    findings = detect_primitives(dataset)

    matching = [
        finding
        for finding in findings
        if finding.primitive == "ASSUME_ADMIN_ROLE"
    ]

    return bool(matching), len(matching)


def classify(expected, detected):
    if expected and detected:
        return "TP"
    if expected and not detected:
        return "FN"
    if not expected and detected:
        return "FP"
    return "TN"


def main():
    # name, trusted, identity_allow, explicit_deny, expected
    cases = [
        ("STS-01-valid-assumption", True, True, False, True),
        ("STS-02-untrusted-user", False, True, False, False),
        ("STS-03-direct-trust-no-identity-allow", True, False, False, True),
        ("STS-04-explicit-identity-deny", True, True, True, False),
    ]

    rows = []

    for case_name, trusted, allow_assume, explicit_deny, expected in cases:
        pmapper_detected, edges, path_length = run_pmapper(
            trusted, allow_assume, explicit_deny
        )
        cloudpath_detected, cloudpath_findings = run_cloudpath(
            trusted, allow_assume, explicit_deny
        )

        rows.append({
            "scenario": case_name,
            "expected_escalation": expected,
            "cloudpath_detected": cloudpath_detected,
            "cloudpath_outcome": classify(expected, cloudpath_detected),
            "cloudpath_matching_findings": cloudpath_findings,
            "pmapper_detected": pmapper_detected,
            "pmapper_outcome": classify(expected, pmapper_detected),
            "pmapper_edges": edges,
            "pmapper_path_length": path_length,
            "tools_agree": cloudpath_detected == pmapper_detected,
        })

    output_file = OUTPUT / "pmapper_comparison_results.csv"

    with output_file.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(json.dumps(rows, indent=2))
    print(f"\nSaved {output_file}")

    if not all(
        row["cloudpath_detected"] == row["expected_escalation"]
        and row["pmapper_detected"] == row["expected_escalation"]
        for row in rows
    ):
        print("\nComparison completed with detection disagreements.")
        print("Review the FN/FP outcomes without changing ground truth.")


if __name__ == "__main__":
    main()
