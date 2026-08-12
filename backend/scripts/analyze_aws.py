"""Collect and analyze an AWS account without modifying cloud resources."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.collectors.aws_collector import collect_aws_iam
from app.detection.path_finder import build_attack_paths
from app.detection.primitives import detect_primitives


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile")
    parser.add_argument("--region")
    parser.add_argument("--output", type=Path, default=Path("aws_analysis.json"))
    args = parser.parse_args()

    dataset = collect_aws_iam(profile=args.profile, region=args.region)
    findings = detect_primitives(dataset)
    result = {
        "account_id": dataset.account_id,
        "principal_count": len(dataset.principals),
        "finding_count": len(findings),
        "findings": [finding.model_dump() for finding in findings],
        "paths": build_attack_paths(findings),
    }
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {args.output} with {len(findings)} findings")


if __name__ == "__main__":
    main()
