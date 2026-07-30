import json
from pathlib import Path

from app.models.domain import Dataset


DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "sample_iam.json"


def load_sample() -> Dataset:
    with DATA_FILE.open("r", encoding="utf-8") as file:
        raw_data = json.load(file)

    return Dataset.model_validate(raw_data)