"""Reproducible synthetic benchmark for the report evaluation chapter."""
from __future__ import annotations

import argparse
import sys
import json
import statistics
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.detection.path_finder import build_attack_paths
from app.detection.primitives import detect_primitives
from app.models.domain import Dataset, Principal, Statement


def synthetic_dataset(size: int) -> Dataset:
    admin = Principal(
        id="role:admin", name="admin", kind="Role",
        trust=[f"user:user-{i}" for i in range(size)],
        policies=[Statement(effect="Allow", actions=["*"], resources=["*"])],
    )
    users = [
        Principal(
            id=f"user:user-{i}", name=f"user-{i}", kind="User",
            policies=[Statement(effect="Allow", actions=["sts:AssumeRole"], resources=["role:admin"])],
        )
        for i in range(size)
    ]
    return Dataset(account_id="benchmark", principals=[*users, admin])


def run(size: int, repetitions: int) -> dict[str, float | int]:
    detection_times: list[float] = []
    path_times: list[float] = []
    finding_count = path_count = 0
    for _ in range(repetitions):
        dataset = synthetic_dataset(size)
        start = time.perf_counter()
        findings = detect_primitives(dataset)
        detection_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        paths = build_attack_paths(findings)
        path_times.append(time.perf_counter() - start)
        finding_count, path_count = len(findings), len(paths)
    return {
        "principals": size + 1,
        "findings": finding_count,
        "paths": path_count,
        "detection_ms_mean": round(statistics.mean(detection_times) * 1000, 3),
        "path_search_ms_mean": round(statistics.mean(path_times) * 1000, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[10, 100, 500, 1000])
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("benchmark_results.json"))
    args = parser.parse_args()
    results = [run(size, args.repetitions) for size in args.sizes]
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
