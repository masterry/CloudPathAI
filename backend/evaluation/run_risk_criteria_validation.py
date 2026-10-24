
"""Validate documented IAM prerequisites against synthetic detection results.

This evaluates detection behavior, not numerical risk-score accuracy
or agreement with independent security experts.
"""

import csv
import json
from pathlib import Path

FOLDER = Path(__file__).resolve().parent


def load_csv(filename):
    with (FOLDER / filename).open(newline="") as file:
        return list(csv.DictReader(file))


def main():
    criteria = load_csv("risk_criteria_validation.csv")
    detections = load_csv("detection_results.csv")

    by_scenario = {row["scenario"]: row for row in detections}

    if len(by_scenario) != len(detections):
        raise ValueError("Duplicate scenario IDs in detection results")

    results = []

    for criterion in criteria:
        positive_id = criterion["positive_scenario"]
        negative_id = criterion["negative_scenario"]
        primitive = criterion["primitive"]

        if positive_id not in by_scenario:
            raise ValueError(f"Missing positive scenario: {positive_id}")

        if negative_id not in by_scenario:
            raise ValueError(f"Missing negative scenario: {negative_id}")

        positive = by_scenario[positive_id]
        negative = by_scenario[negative_id]

        positive_detected = (
            primitive in positive["detected_primitives"].split(";")
            and positive["outcome"] == "TP"
        )

        negative_suppressed = (
            negative["detected_primitives"] == "NONE"
            and negative["outcome"] == "TN"
        )

        results.append({
            **criterion,
            "positive_detected": positive_detected,
            "negative_suppressed": negative_suppressed,
            "criterion_passed": (
                positive_detected and negative_suppressed
            ),
        })

    output_file = FOLDER / "risk_criteria_results.csv"

    with output_file.open("w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(results[0].keys()),
        )
        writer.writeheader()
        writer.writerows(results)

    passed = sum(row["criterion_passed"] for row in results)

    summary = {
        "validation_type": "standards_informed_synthetic_prerequisite",
        "criteria_total": len(results),
        "criteria_passed": passed,
        "criteria_failed": len(results) - passed,
        "positive_scenarios_detected": sum(
            row["positive_detected"] for row in results
        ),
        "negative_scenarios_suppressed": sum(
            row["negative_suppressed"] for row in results
        ),
        "independent_expert_validation": False,
        "numerical_risk_score_calibration": False,
    }

    (FOLDER / "risk_criteria_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    print(json.dumps(summary, indent=2))
    print("Saved evaluation/risk_criteria_results.csv")
    print("Saved evaluation/risk_criteria_summary.json")


if __name__ == "__main__":
    main()
