
import csv
from pathlib import Path

from app.detection.risk_scoring import RiskFactors, calculate_score

# Factors taken from the seven implemented escalation detectors.
FACTORS = {
    "ASSUME_ADMIN_ROLE": RiskFactors(100, 90, 95),
    "CREATE_ACCESS_KEY": RiskFactors(100, 90, 95),
    "PASSROLE_LAMBDA": RiskFactors(100, 90, 95),
    "MODIFY_OWN_ROLE": RiskFactors(90, 75, 90),
    "CREATE_POLICY_VERSION": RiskFactors(95, 80, 90),
    "ATTACH_USER_POLICY": RiskFactors(95, 85, 85),
    "UPDATE_ASSUME_ROLE_POLICY": RiskFactors(100, 70, 85),
}

ROOT = Path(__file__).resolve().parent
benchmark_path = ROOT / "risk_readiness_benchmark.csv"
output_path = ROOT / "risk_readiness_results.csv"

results = []

with benchmark_path.open(newline="", encoding="utf-8") as file:
    for row in csv.DictReader(file):
        higher = row["higher_readiness"]
        lower = row["lower_readiness"]

        higher_score = calculate_score(FACTORS[higher])
        lower_score = calculate_score(FACTORS[lower])

        if higher_score > lower_score:
            outcome = "consistent"
        elif higher_score == lower_score:
            outcome = "tie"
        else:
            outcome = "inconsistent"

        results.append({
            **row,
            "higher_score": higher_score,
            "lower_score": lower_score,
            "outcome": outcome,
        })

with output_path.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

consistent = sum(row["outcome"] == "consistent" for row in results)
ties = sum(row["outcome"] == "tie" for row in results)
inconsistent = sum(row["outcome"] == "inconsistent" for row in results)

print(f"Benchmark comparisons: {len(results)}")
print(f"Consistent: {consistent}")
print(f"Ties: {ties}")
print(f"Inconsistent: {inconsistent}")
print(f"Strict agreement: {consistent}/{len(results)}")

for row in results:
    print(
        f'{row["comparison_id"]}: '
        f'{row["higher_readiness"]} ({row["higher_score"]}) > '
        f'{row["lower_readiness"]} ({row["lower_score"]}) '
        f'[{row["outcome"]}]'
    )

print(f"Results saved to: {output_path}")
