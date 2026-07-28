#!/usr/bin/env python3
"""Detection-quality regression gate.

Runs the full test suite and fails (exit 1) if any metric is worse than
the committed floor in test_repos/baseline_metrics.json. Run this before
every release / merge. Requires Ollama running locally.

Usage:
  python3 ci/regression_gate.py            # run suite, then compare
  python3 ci/regression_gate.py --skip-run # compare existing test_results.json
  python3 ci/regression_gate.py --update   # rewrite baseline from current results
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "test_repos", "test_results.json")
BASELINE = os.path.join(ROOT, "test_repos", "baseline_metrics.json")


def aggregate(results: list) -> dict:
    expected = sum(r["total_expected"] for r in results)
    found = sum(r["total_found"] for r in results)
    type_correct = sum(r["type_correct"] for r in results)
    return {
        "detection_rate": round(100.0 * found / expected, 1) if expected else 0,
        "type_accuracy": round(100.0 * type_correct / found, 1) if found else 0,
        "false_positives": sum(r["false_positives"] for r in results),
        "missed": sum(r["missed"] for r in results),
    }


def main():
    if "--skip-run" not in sys.argv:
        print("Running detection test suite...")
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "test_repos", "run_tests.py")],
            cwd=ROOT)
        if proc.returncode != 0:
            print("Test suite failed to run")
            return 1

    with open(RESULTS) as f:
        current = aggregate(json.load(f))
    print(f"Current:  {current}")

    if "--update" in sys.argv:
        with open(BASELINE, "w") as f:
            json.dump(current, f, indent=2)
        print(f"Baseline updated: {BASELINE}")
        return 0

    if not os.path.exists(BASELINE):
        print(f"No baseline at {BASELINE} — run with --update to create one")
        return 1

    with open(BASELINE) as f:
        base = json.load(f)
    print(f"Baseline: {base}")

    failures = []
    if current["detection_rate"] < base["detection_rate"]:
        failures.append("detection_rate dropped "
                        f"{base['detection_rate']} -> {current['detection_rate']}")
    if current["type_accuracy"] < base["type_accuracy"]:
        failures.append("type_accuracy dropped "
                        f"{base['type_accuracy']} -> {current['type_accuracy']}")
    if current["false_positives"] > base["false_positives"]:
        failures.append("false_positives rose "
                        f"{base['false_positives']} -> {current['false_positives']}")

    if failures:
        print("\n❌ REGRESSION GATE FAILED:")
        for f_ in failures:
            print(f"   - {f_}")
        return 1
    print("\n✅ Regression gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
