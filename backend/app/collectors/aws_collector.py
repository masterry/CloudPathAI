"""Read-only AWS IAM collector.

The collector uses IAM List/Get APIs only. It never changes cloud resources.
Run it with a least-privilege audit role and temporary credentials.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

import boto3

from app.models.domain import Dataset, Principal, Statement
from app.policy.parser import parse_policy_document


def _principal_id(arn: str) -> str:
    if ":user/" in arn:
        return f"user:{arn.rsplit('/', 1)[-1]}"
    if ":role/" in arn:
        return f"role:{arn.rsplit('/', 1)[-1]}"
    if arn.endswith(".amazonaws.com"):
        return f"service:{arn}"
    return arn


def _decode_document(document: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(document, str):
        return json.loads(unquote(document))
    return document


def _trust_principals(document: dict[str, Any] | str) -> list[str]:
    decoded = _decode_document(document)
    principals: set[str] = set()
    statements = decoded.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue

        raw = statement.get("Principal", {})
        if isinstance(raw, str):
            raw = {"AWS": raw}

        for key in ("AWS", "Service", "Federated"):
            values = raw.get(key, []) if isinstance(raw, dict) else []
            if not isinstance(values, list):
                values = [values]
            principals.update(_principal_id(str(value)) for value in values)

    return sorted(principals)


def _managed_policy_statements(iam: Any, policy_arn: str) -> list[Statement]:
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=policy["DefaultVersionId"],
    )["PolicyVersion"]
    document = _decode_document(version["Document"])
    return parse_policy_document(document, source_policy_arn=policy_arn)


def _inline_policy_statements(document: dict[str, Any] | str) -> list[Statement]:
    return parse_policy_document(_decode_document(document))


def _attached_policy_arns(iam: Any, paginator_name: str, **kwargs: str) -> list[str]:
    arns: list[str] = []
    for page in iam.get_paginator(paginator_name).paginate(**kwargs):
        arns.extend(
            policy["PolicyArn"]
            for policy in page.get("AttachedPolicies", [])
        )
    return arns


def _group_policies(iam: Any, group_name: str) -> tuple[list[Statement], list[str]]:
    statements: list[Statement] = []
    attached_arns = _attached_policy_arns(
        iam,
        "list_attached_group_policies",
        GroupName=group_name,
    )
    for policy_arn in attached_arns:
        statements.extend(_managed_policy_statements(iam, policy_arn))

    for page in iam.get_paginator("list_group_policies").paginate(GroupName=group_name):
        for policy_name in page.get("PolicyNames", []):
            document = iam.get_group_policy(
                GroupName=group_name,
                PolicyName=policy_name,
            )["PolicyDocument"]
            statements.extend(_inline_policy_statements(document))

    return statements, attached_arns


def _user_policies(iam: Any, user_name: str) -> tuple[list[Statement], list[str]]:
    statements: list[Statement] = []
    attached_arns = _attached_policy_arns(
        iam,
        "list_attached_user_policies",
        UserName=user_name,
    )
    for policy_arn in attached_arns:
        statements.extend(_managed_policy_statements(iam, policy_arn))

    for page in iam.get_paginator("list_user_policies").paginate(UserName=user_name):
        for policy_name in page.get("PolicyNames", []):
            document = iam.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
            )["PolicyDocument"]
            statements.extend(_inline_policy_statements(document))

    # IAM users inherit identity-policy permissions from all groups they belong to.
    for page in iam.get_paginator("list_groups_for_user").paginate(UserName=user_name):
        for group in page.get("Groups", []):
            group_statements, group_arns = _group_policies(iam, group["GroupName"])
            statements.extend(group_statements)
            attached_arns.extend(group_arns)

    return statements, sorted(set(attached_arns))


def _role_policies(iam: Any, role_name: str) -> tuple[list[Statement], list[str]]:
    statements: list[Statement] = []
    attached_arns = _attached_policy_arns(
        iam,
        "list_attached_role_policies",
        RoleName=role_name,
    )
    for policy_arn in attached_arns:
        statements.extend(_managed_policy_statements(iam, policy_arn))

    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
        for policy_name in page.get("PolicyNames", []):
            document = iam.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
            )["PolicyDocument"]
            statements.extend(_inline_policy_statements(document))

    return statements, attached_arns


def collect_aws_iam(*, profile: str | None = None, region: str | None = None) -> Dataset:
    """Collect users, roles, effective identity policies, and role trust."""
    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    principals: list[Principal] = []

    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            name = user["UserName"]
            policies, attached_arns = _user_policies(iam, name)
            principals.append(
                Principal(
                    id=f"user:{name}",
                    arn=user["Arn"],
                    name=name,
                    kind="User",
                    policies=policies,
                    attached_managed_policy_arns=attached_arns,
                )
            )

    for page in iam.get_paginator("list_roles").paginate():
        for role in page.get("Roles", []):
            name = role["RoleName"]
            policies, attached_arns = _role_policies(iam, name)
            principals.append(
                Principal(
                    id=f"role:{name}",
                    arn=role["Arn"],
                    name=name,
                    kind="Role",
                    policies=policies,
                    trust=_trust_principals(role["AssumeRolePolicyDocument"]),
                    attached_managed_policy_arns=attached_arns,
                )
            )

    return Dataset(account_id=account_id, principals=principals)
