
"""Offline PMapper STS escalation smoke test using synthetic IAM data."""

import json

import evaluation.pmapper_compat  # Apply Python 3.11 compatibility aliases.

from principalmapper.common.graphs import Graph
from principalmapper.common.nodes import Node
from principalmapper.common.policies import Policy
from principalmapper.graphing.sts_edges import STSEdgeChecker
from principalmapper.querying.presets.privesc import can_privesc
import principalmapper


ACCOUNT_ID = "123456789012"
USER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/test-user"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/AdminRole"


def make_policy(allow_assume_role):
    actions = ["sts:AssumeRole"] if allow_assume_role else ["s3:ListBucket"]

    return Policy(
        arn=f"arn:aws:iam::{ACCOUNT_ID}:policy/TestPolicy",
        name="TestPolicy",
        policy_doc={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": actions,
                "Resource": ROLE_ARN,
            }],
        },
    )


def make_node(arn, identifier, policies, trust_policy, is_admin):
    return Node(
        arn=arn,
        id_value=identifier,
        attached_policies=policies,
        group_memberships=[],
        trust_policy=trust_policy,
        instance_profile=None,
        num_access_keys=0,
        active_password=False,
        is_admin=is_admin,
        permissions_boundary=None,
        has_mfa=False,
        tags={},
    )


def run_case(case_name, trusted_principal, allow_assume_role, expected):
    policy = make_policy(allow_assume_role)

    user = make_node(
        USER_ARN, "AIDAEXAMPLE001", [policy], None, False
    )

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": trusted_principal},
            "Action": "sts:AssumeRole",
        }],
    }

    admin_role = make_node(
        ROLE_ARN, "AROAEXAMPLE001", [], trust_policy, True
    )

    nodes = [user, admin_role]

    # PMapper generates edges from policies and trust relationships.
    edges = STSEdgeChecker(None).return_edges(nodes)

    graph = Graph(
        nodes=nodes,
        edges=edges,
        policies=[policy],
        groups=[],
        metadata={
            "account_id": ACCOUNT_ID,
            "pmapper_version": principalmapper.__version__,
        },
    )

    detected, path = can_privesc(graph, user)

    result = {
        "case": case_name,
        "expected": expected,
        "detected": bool(detected),
        "edge_count": len(edges),
        "path_length": len(path) if path else 0,
        "passed": bool(detected) == expected,
    }

    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    positive = run_case(
        "STS-01-valid-assumption",
        USER_ARN,
        True,
        True,
    )

    negative = run_case(
        "STS-02-untrusted-user",
        f"arn:aws:iam::{ACCOUNT_ID}:role/OtherRole",
        True,
        False,
    )

    if not all([positive["passed"], negative["passed"]]):
        raise SystemExit("One or more PMapper test cases failed.")

    print("\nBoth offline PMapper smoke tests passed.")
