
import csv
import math
from pathlib import Path

from scipy.stats import spearmanr

FOLDER = Path(__file__).resolve().parent
MODEL_FILE = FOLDER / "risk_validation_template.csv"
REVIEWER_1 = FOLDER / "risk_review_reviewer1.csv"
REVIEWER_2 = FOLDER / "risk_review_reviewer2.csv"


def load_rows(path):
    with path.open(newline="") as file:
        return list(csv.DictReader(file))


def get_reviews(path):
    reviews = {}
    for row in load_rows(path):
        score = row["reviewer_score"].strip()
        if score:
            value = float(score)
            if not math.isfinite(value) or not 0 <= value <= 100:
                raise ValueError(
                    f"Invalid reviewer score in {path}: {score}"
                )
            reviews[row["scenario"]] = value
    return reviews


if not REVIEWER_1.exists() or not REVIEWER_2.exists():
    print("Reviewer files are not ready yet.")
    print("Create risk_review_reviewer1.csv and risk_review_reviewer2.csv")
    raise SystemExit(0)

model_rows = load_rows(MODEL_FILE)
review_1 = get_reviews(REVIEWER_1)
review_2 = get_reviews(REVIEWER_2)

model_scores = []
expert_scores = []
rater_1_scores = []
rater_2_scores = []

for row in model_rows:
    scenario = row["scenario"]

    if scenario not in review_1 or scenario not in review_2:
        continue

    model_scores.append(float(row["cloudpath_score"]))
    rater_1_scores.append(review_1[scenario])
    rater_2_scores.append(review_2[scenario])
    expert_scores.append(
        (review_1[scenario] + review_2[scenario]) / 2
    )

if len(model_scores) < 3:
    print("Not enough fully rated scenarios for correlation.")
    raise SystemExit(0)

model_corr = spearmanr(model_scores, expert_scores)
reviewer_corr = spearmanr(rater_1_scores, rater_2_scores)

print("Fully rated scenarios:", len(model_scores))
print("CloudPathAI vs expert Spearman rho:", model_corr.statistic)
print("CloudPathAI vs expert p-value:", model_corr.pvalue)
print("Reviewer agreement (Spearman rho):", reviewer_corr.statistic)
print("Reviewer agreement p-value:", reviewer_corr.pvalue)
