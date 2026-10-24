
import csv
import json
import math
import random
from pathlib import Path
from statistics import mean, median

from scipy.stats import spearmanr

FOLDER = Path(__file__).resolve().parent

INPUT = FOLDER / "risk_simulation_results.csv"
OUTPUT = FOLDER / "risk_uncertainty_results.csv"
SUMMARY = FOLDER / "risk_uncertainty_summary.json"

SIMULATIONS = 5000
SEED = 42
UNCERTAINTY = 10

# Same reference weights as the baseline simulation.
WEIGHTS = (0.40, 0.40, 0.20)

rng = random.Random(SEED)

with INPUT.open(newline="") as file:
    findings = list(csv.DictReader(file))

if len(findings) < 3:
    raise ValueError("At least three scenarios are required.")

model_scores = [
    float(row["cloudpath_score"])
    for row in findings
]

baseline_factors = [
    (
        float(row["reference_impact"]),
        float(row["reference_exploitability"]),
        float(row["reference_confidence"]),
    )
    for row in findings
]


def sample_factor(value):
    """Sample uniformly within ±10 points, bounded to 0–100."""
    low = max(0.0, value - UNCERTAINTY)
    high = min(100.0, value + UNCERTAINTY)
    return rng.uniform(low, high)


def calculate_reference(factors):
    return sum(
        weight * factor
        for weight, factor in zip(WEIGHTS, factors)
    )


results = []

for simulation in range(1, SIMULATIONS + 1):
    reference_scores = []

    for factors in baseline_factors:
        sampled_factors = [
            sample_factor(value)
            for value in factors
        ]

        reference_scores.append(
            calculate_reference(sampled_factors)
        )

    correlation = spearmanr(
        model_scores,
        reference_scores
    ).statistic

    mae = mean(
        abs(model - reference)
        for model, reference in zip(
            model_scores, reference_scores
        )
    )

    results.append({
        "simulation": simulation,
        "spearman_rho": float(correlation),
        "mean_absolute_error": float(mae),
    })

with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "simulation",
            "spearman_rho",
            "mean_absolute_error",
        ],
    )
    writer.writeheader()
    writer.writerows(results)


def percentile(values, percentage):
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentage / 100
    lower = math.floor(position)
    upper = math.ceil(position)

    return (
        ordered[lower] * (upper - position)
        + ordered[upper] * (position - lower)
        if lower != upper
        else ordered[lower]
    )


correlations = [
    row["spearman_rho"] for row in results
]
errors = [
    row["mean_absolute_error"] for row in results
]

summary = {
    "evaluation_type": "simulation_based_factor_uncertainty",
    "scenario_count": len(findings),
    "simulations": SIMULATIONS,
    "random_seed": SEED,
    "factor_uncertainty_points": UNCERTAINTY,
    "sampling_method": (
        "Independent uniform perturbations within ±10 "
        "points, clipped to the 0–100 range."
    ),
    "reference_weights": {
        "impact": WEIGHTS[0],
        "exploitability": WEIGHTS[1],
        "confidence": WEIGHTS[2],
    },
    "spearman_rho": {
        "mean": mean(correlations),
        "median": median(correlations),
        "minimum": min(correlations),
        "maximum": max(correlations),
        "percentile_2_5": percentile(correlations, 2.5),
        "percentile_97_5": percentile(correlations, 97.5),
    },
    "mean_absolute_error": {
        "mean": mean(errors),
        "median": median(errors),
        "minimum": min(errors),
        "maximum": max(errors),
        "percentile_2_5": percentile(errors, 2.5),
        "percentile_97_5": percentile(errors, 97.5),
    },
    "limitations": [
        "Reference factor values are hypothetical.",
        "Uniform uncertainty bounds are modeling assumptions.",
        "Perturbations are independently sampled per scenario.",
        "Results do not represent independent expert validation.",
        "Synthetic configurations were not exploited in AWS.",
        "The analysis does not test context-sensitive model scoring.",
    ],
}

with SUMMARY.open("w") as file:
    json.dump(summary, file, indent=2)

print(json.dumps(summary, indent=2))
print(f"\nSaved {OUTPUT}")
print(f"Saved {SUMMARY}")
