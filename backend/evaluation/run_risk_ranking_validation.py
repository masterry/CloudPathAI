
"""Evaluate internal consistency of CloudPathAI's primitive risk rankings."""

import csv
import itertools
import json
from collections import Counter
from pathlib import Path

from app.detection.risk_scoring import RiskFactors, calculate_score

OUTPUT = Path(__file__).resolve().parent

# Current factor assignments from app/detection/primitives.py.
# Keep synchronized with the detector until factors are centralized.
FACTORS = {
    "ASSUME_ADMIN_ROLE": (100, 90, 95),
    "CREATE_ACCESS_KEY": (100, 90, 95),
    "PASSROLE_LAMBDA": (100, 90, 95),
    "MODIFY_OWN_ROLE": (90, 75, 90),
    "CREATE_POLICY_VERSION": (95, 80, 90),
    "ATTACH_USER_POLICY": (95, 85, 85),
    "UPDATE_ASSUME_ROLE_POLICY": (100, 70, 85),
}


def dominates(a, b):
    """True when a is no worse in all factors and better in at least one."""
    return all(x >= y for x, y in zip(a, b)) and any(
        x > y for x, y in zip(a, b)
    )


def main():
    scores = {
        name: calculate_score(RiskFactors(*values))
        for name, values in FACTORS.items()
    }

    rows = []
    for (name_a, factors_a), (name_b, factors_b) in itertools.combinations(
        FACTORS.items(), 2
    ):
        if dominates(factors_a, factors_b):
            expected = "A>B"
            consistent = scores[name_a] > scores[name_b]
        elif dominates(factors_b, factors_a):
            expected = "B>A"
            consistent = scores[name_b] > scores[name_a]
        else:
            expected = "not_comparable"
            consistent = None

        rows.append({
            "primitive_a": name_a,
            "primitive_b": name_b,
            "score_a": scores[name_a],
            "score_b": scores[name_b],
            "factor_relationship": expected,
            "dominance_consistent": consistent,
            "score_tied": scores[name_a] == scores[name_b],
        })

    dominance_rows = [
        row for row in rows
        if row["factor_relationship"] != "not_comparable"
    ]

    summary = {
        "primitive_count": len(FACTORS),
        "pair_count": len(rows),
        "dominance_comparisons": len(dominance_rows),
        "dominance_consistent": sum(
            row["dominance_consistent"] for row in dominance_rows
        ),
        "score_ties": sum(row["score_tied"] for row in rows),
        "unique_scores": len(set(scores.values())),
        "score_distribution": dict(Counter(scores.values())),
    }

    csv_path = OUTPUT / "risk_ranking_pairs.csv"
    with csv_path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    summary_path = OUTPUT / "risk_ranking_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")

    print(json.dumps(summary, indent=2))
    print(f"Saved {csv_path}")
    print(f"Saved {summary_path}")


if __name__ == "__main__":
    main()
