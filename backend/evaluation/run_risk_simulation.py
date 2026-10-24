
import csv
import json
from pathlib import Path

from scipy.stats import spearmanr

FOLDER = Path(__file__).resolve().parent
INPUT = FOLDER / "risk_validation_template.csv"
OUTPUT = FOLDER / "risk_simulation_results.csv"
SUMMARY = FOLDER / "risk_simulation_summary.json"

# Hypothetical reference factors, not human reviewer scores.
# Values are explicit modeling assumptions.
REFERENCE = {
    "ASSUME_ADMIN_ROLE": (100, 95, 95),
    "CREATE_ACCESS_KEY": (100, 90, 90),
    "PASSROLE_LAMBDA": (100, 85, 90),
    "MODIFY_OWN_ROLE": (90, 85, 85),
    "CREATE_POLICY_VERSION": (95, 75, 80),
    "ATTACH_USER_POLICY": (95, 85, 85),
    "UPDATE_ASSUME_ROLE_POLICY": (100, 40, 65),
}


def reference_score(impact, exploitability, confidence):
    return 0.40 * impact + 0.40 * exploitability + 0.20 * confidence


with INPUT.open(newline="") as file:
    findings = list(csv.DictReader(file))

results = []

for finding in findings:
    primitive = finding["primitive"]
    impact, exploitability, confidence = REFERENCE[primitive]

    model_score = float(finding["cloudpath_score"])
    simulated_score = reference_score(
        impact, exploitability, confidence
    )

    results.append({
        "scenario": finding["scenario"],
        "primitive": primitive,
        "cloudpath_score": model_score,
        "reference_impact": impact,
        "reference_exploitability": exploitability,
        "reference_confidence": confidence,
        "simulated_reference_score": simulated_score,
        "absolute_difference": abs(model_score - simulated_score),
    })

with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

model_scores = [row["cloudpath_score"] for row in results]
reference_scores = [
    row["simulated_reference_score"] for row in results
]

correlation = spearmanr(model_scores, reference_scores)
mae = sum(row["absolute_difference"] for row in results) / len(results)

summary = {
    "evaluation_type": "simulation_based",
    "scenario_count": len(results),
    "spearman_rho": float(correlation.statistic),
    "mean_absolute_error": mae,
    "reference_weights": {
        "impact": 0.40,
        "exploitability": 0.40,
        "confidence": 0.20,
    },
    "limitations": [
        "Reference scores are hypothetical modeling assumptions.",
        "No independent expert ratings were collected for this simulation.",
        "Synthetic scenarios do not demonstrate live AWS exploitation.",
        "Reference factors are defined by primitive, not individual IAM context.",
    ],
}

with SUMMARY.open("w") as file:
    json.dump(summary, file, indent=2)

print(json.dumps(summary, indent=2))
print(f"\nSaved {OUTPUT}")
print(f"Saved {SUMMARY}")
