
import csv
from pathlib import Path

from app.collectors.sample_loader import load_sample
from app.detection.primitives import detect_primitives

OUTPUT = Path(__file__).resolve().parent / "risk_scores.csv"

dataset = load_sample()
findings = detect_primitives(dataset)

rows = []

for finding in findings:
    rows.append({
        "finding_id": finding.id,
        "primitive": finding.primitive,
        "source": finding.source,
        "target": finding.target,
        "cloudpath_score": finding.score,
        "severity": finding.severity,
        "expert_score": "",
    })

with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "finding_id",
            "primitive",
            "source",
            "target",
            "cloudpath_score",
            "severity",
            "expert_score",
        ],
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"Exported {len(rows)} findings")
print(f"Saved to {OUTPUT}")

for row in rows:
    print(
        row["primitive"],
        "=>",
        row["cloudpath_score"],
        row["severity"],
    )
