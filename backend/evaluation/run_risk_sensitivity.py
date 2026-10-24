
import csv
import json
from pathlib import Path

from scipy.stats import spearmanr

FOLDER = Path(__file__).resolve().parent

INPUT = FOLDER / "risk_simulation_results.csv"
OUTPUT = FOLDER / "risk_sensitivity_results.csv"
SUMMARY = FOLDER / "risk_sensitivity_summary.json"

WEIGHT_SCHEMES = {
    "balanced": (0.40, 0.40, 0.20),
    "impact_focused": (0.60, 0.25, 0.15),
    "exploitability_focused": (0.25, 0.60, 0.15),
    "confidence_focused": (0.30, 0.30, 0.40),
    "equal_weights": (1 / 3, 1 / 3, 1 / 3),
}

with INPUT.open(newline="") as file:
    findings = list(csv.DictReader(file))

results = []

for name, weights in WEIGHT_SCHEMES.items():
    model_scores = []
    reference_scores = []

    for finding in findings:
        impact = float(finding["reference_impact"])
        exploitability = float(
            finding["reference_exploitability"]
        )
        confidence = float(finding["reference_confidence"])

        reference = (
            weights[0] * impact
            + weights[1] * exploitability
            + weights[2] * confidence
        )

        model_scores.append(float(finding["cloudpath_score"]))
        reference_scores.append(reference)

    correlation = spearmanr(model_scores, reference_scores)

    mae = sum(
        abs(model - reference)
        for model, reference in zip(
            model_scores, reference_scores
        )
    ) / len(model_scores)

    results.append({
        "scheme": name,
        "impact_weight": weights[0],
        "exploitability_weight": weights[1],
        "confidence_weight": weights[2],
        "spearman_rho": float(correlation.statistic),
        "mean_absolute_error": round(mae, 4),
    })

with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=results[0].keys()
    )
    writer.writeheader()
    writer.writerows(results)

summary = {
    "evaluation_type": "weight_sensitivity_analysis",
    "scenario_count": len(findings),
    "weight_schemes_tested": len(results),
    "minimum_spearman_rho": min(
        row["spearman_rho"] for row in results
    ),
    "maximum_spearman_rho": max(
        row["spearman_rho"] for row in results
    ),
    "results": results,
    "limitations": [
        "All schemes reuse the same hypothetical reference factors.",
        "The seven scenarios are synthetic.",
        "Weight variation does not provide independent ground truth.",
    ],
}

with SUMMARY.open("w") as file:
    json.dump(summary, file, indent=2)

print(json.dumps(summary, indent=2))
print(f"\nSaved {OUTPUT}")
print(f"Saved {SUMMARY}")
