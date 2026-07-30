from collections import defaultdict, deque
from typing import Any

from app.models.domain import Finding


def build_attack_paths(
    findings: list[Finding],
) -> list[dict[str, Any]]:
    adjacency: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        adjacency[finding.source].append(finding)

    paths: list[dict[str, Any]] = []

    for starting_principal in adjacency:
        queue = deque(
            [
                (
                    starting_principal,
                    [],
                    {starting_principal},
                )
            ]
        )

        while queue:
            current_node, current_findings, visited = queue.popleft()

            for finding in adjacency.get(current_node, []):
                next_node = finding.target
                updated_findings = current_findings + [finding]

                paths.append(
                    {
                        "source": starting_principal,
                        "target": next_node,
                        "score": max(
                            item.score for item in updated_findings
                        ),
                        "severity": _highest_severity(updated_findings),
                        "steps": [
                            {
                                "finding_id": item.id,
                                "primitive": item.primitive,
                                "source": item.source,
                                "target": item.target,
                                "title": item.title,
                            }
                            for item in updated_findings
                        ],
                    }
                )

                # Record self-loop findings, but do not traverse them again.
                if next_node == current_node:
                    continue

                # Prevent cycles through already visited principals.
                if next_node in visited:
                    continue

                queue.append(
                    (
                        next_node,
                        updated_findings,
                        visited | {next_node},
                    )
                )

    return paths


def _highest_severity(findings: list[Finding]) -> str:
    severity_order = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    return max(
        findings,
        key=lambda finding: severity_order[finding.severity],
    ).severity