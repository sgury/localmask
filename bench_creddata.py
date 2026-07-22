#!/usr/bin/env python3
"""
LocalMask × CredData benchmark runner
======================================
Runs LocalMask against Samsung/CredData and computes TP/FP/TN/FN/Precision/Recall/F1,
matching the published table at https://github.com/Samsung/CredData#benchmark-result

Prerequisites
-------------
1. Clone CredData and download the dataset (Linux or Docker — see note below):

   git clone https://github.com/Samsung/CredData /tmp/CredData
   cd /tmp/CredData
   pip install -r requirements.txt
   python download_data.py          # downloads ~297 repos into data/

   Docker (macOS/Windows):
   docker run --rm -v /tmp/CredData:/data python:3.10 bash -c \
     "pip install -r /data/requirements.txt && cd /data && python download_data.py"

2. Set CREDDATA_DIR to the path of the cloned + downloaded repo:
   export CREDDATA_DIR=/tmp/CredData

3. Run:
   cd /path/to/localmask-oss
   python bench_creddata.py [--pro] [--langs he] [--limit N]

   --pro      Use the Pro engine (requires files11_mcp on PYTHONPATH or installed).
              Default: free regex engine only.
   --langs    LOCALMASK_LANGS value (default: none). Use "he" for Hebrew PII.
   --limit N  Only score the first N labeled files (useful for a quick smoke test).
   --out FILE Write JSON results to FILE (default: creddata_results.json).

How it works
------------
CredData's metadata (meta/snapshot.csv or meta/*.csv) labels every suspicious line
as True (real credential) or False (test/doc placeholder). This script:

1. Reads CredData's ground-truth labels (file path + line number + True/False).
2. Runs LocalMask's regex scanner on each labeled file.
3. For each labeled line, checks whether LocalMask flagged that line.
4. Computes TP/FP/TN/FN and derives Precision/Recall/F1.

The scoring method matches CredData's published benchmark: a detection is a TP
if LocalMask flags any credential on the same line as a ground-truth True label.
"""

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

# ── CLI args ──────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="LocalMask × CredData benchmark")
parser.add_argument("--pro", action="store_true",
                    help="Use Pro engine (LOCALMASK_EDITION=pro)")
parser.add_argument("--langs", default="",
                    help="LOCALMASK_LANGS value (e.g. 'he' or 'all')")
parser.add_argument("--limit", type=int, default=0,
                    help="Limit to first N labeled files (0 = all)")
parser.add_argument("--out", default="creddata_results.json",
                    help="Output JSON file path")
parser.add_argument("--creddata-dir", default=os.environ.get("CREDDATA_DIR", "/tmp/CredData"),
                    help="Path to cloned + downloaded CredData repo")
parser.add_argument("--sensitivity", default="standard",
                    choices=["minimal", "standard", "strict"],
                    help="LocalMask sensitivity level")
args = parser.parse_args()

CREDDATA_DIR = Path(args.creddata_dir)
DATA_DIR = CREDDATA_DIR / "data"

if not CREDDATA_DIR.exists():
    sys.exit(f"ERROR: CredData dir not found: {CREDDATA_DIR}\n"
             f"Clone it and run download_data.py first — see docstring above.")
if not DATA_DIR.exists():
    sys.exit(f"ERROR: {DATA_DIR} not found — run 'python download_data.py' inside {CREDDATA_DIR}")

# ── Engine setup ──────────────────────────────────────────────────────────────

if args.pro:
    os.environ["LOCALMASK_EDITION"] = "pro"
    os.environ["LOCALMASK_ACCEPT_LEGACY_KEYS"] = "1"
else:
    os.environ.setdefault("LOCALMASK_EDITION", "free")
    os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"  # disable LLM

if args.langs:
    os.environ["LOCALMASK_LANGS"] = args.langs

from regex_rules_safe import RegexRulesSafe  # noqa: E402  (after env set)

# ── Load CredData ground truth ────────────────────────────────────────────────
# CredData stores metadata in meta/ as CSV files, one per repo.
# Each row: RepoName, FilePath, LineStart, LineEnd, GroundTruth, CredType, ...
# GroundTruth: "True" = real credential, "False" = placeholder/test data.

print(f"Loading CredData ground truth from {CREDDATA_DIR}/meta/ ...")

# ground_truth[abs_file_path] = {line_num: bool}  (True = real credential)
ground_truth: dict[str, dict[int, bool]] = {}

meta_dir = CREDDATA_DIR / "meta"
csv_files = list(meta_dir.glob("*.csv")) if meta_dir.exists() else []

# Some CredData versions use a single snapshot.csv
snapshot = CREDDATA_DIR / "snapshot.json"
if not csv_files and snapshot.exists():
    with open(snapshot) as f:
        snap = json.load(f)
    for entry in snap:
        rel = entry.get("FilePath", "")
        line = entry.get("LineStart", 0)
        real = str(entry.get("GroundTruth", "False")).lower() == "true"
        abs_path = str(DATA_DIR / rel)
        ground_truth.setdefault(abs_path, {})[line] = real
elif csv_files:
    for csv_path in csv_files:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                rel = row.get("FilePath", "")
                try:
                    line = int(row.get("LineStart", 0))
                except ValueError:
                    continue
                real = str(row.get("GroundTruth", "False")).lower() == "true"
                abs_path = str(DATA_DIR / rel)
                ground_truth.setdefault(abs_path, {})[line] = real
else:
    sys.exit(f"ERROR: No meta/*.csv or snapshot.json found in {CREDDATA_DIR}.\n"
             f"Make sure you cloned the full CredData repo.")

total_labeled_files = len(ground_truth)
total_labeled_lines = sum(len(v) for v in ground_truth.values())
total_true = sum(sum(1 for v in d.values() if v) for d in ground_truth.values())
total_false = total_labeled_lines - total_true

print(f"  {total_labeled_files:,} labeled files")
print(f"  {total_labeled_lines:,} labeled lines  ({total_true:,} True / {total_false:,} False)")

# ── Scan and score ────────────────────────────────────────────────────────────

files = list(ground_truth.keys())
if args.limit:
    files = files[:args.limit]
    print(f"  (limiting to first {args.limit} files)")

TP = FP = FN = 0
errors = 0
t0 = time.time()

for i, fpath in enumerate(files, 1):
    if i % 200 == 0:
        elapsed = time.time() - t0
        rate = i / elapsed
        remaining = (len(files) - i) / rate
        print(f"  [{i}/{len(files)}] TP={TP} FP={FP} FN={FN} "
              f"({rate:.0f} files/s, ~{remaining:.0f}s left)")

    gt_lines = ground_truth[fpath]   # {line_num: bool}

    if not os.path.exists(fpath):
        # File missing from download — count True labels as FN
        fn_here = sum(1 for v in gt_lines.values() if v)
        FN += fn_here
        errors += 1
        continue

    try:
        content = open(fpath, errors="ignore").read()
    except OSError:
        fn_here = sum(1 for v in gt_lines.values() if v)
        FN += fn_here
        errors += 1
        continue

    detections = RegexRulesSafe.scan_file(fpath, content, args.sensitivity)
    detected_lines = {d["line"] for d in detections}

    for line_num, is_real in gt_lines.items():
        flagged = line_num in detected_lines
        if is_real and flagged:
            TP += 1
        elif not is_real and flagged:
            FP += 1
        elif is_real and not flagged:
            FN += 1
        # TN (not real, not flagged) — not counted toward score but tracked below

elapsed = time.time() - t0

# TN = all labeled False lines that were not flagged
# For accuracy we need TN — approximate from total labeled lines
scanned_true = sum(sum(1 for v in ground_truth[f].values() if v)
                   for f in files if f in ground_truth)
scanned_false = sum(sum(1 for v in ground_truth[f].values() if not v)
                    for f in files if f in ground_truth)
TN = scanned_false - FP

precision  = TP / (TP + FP)  if (TP + FP)  else 0.0
recall     = TP / (TP + FN)  if (TP + FN)  else 0.0
f1         = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
fpr        = FP / (FP + TN)  if (FP + TN)  else 0.0
fnr        = FN / (FN + TP)  if (FN + TP)  else 0.0
accuracy   = (TP + TN) / (TP + FP + TN + FN) if (TP + FP + TN + FN) else 0.0

# ── Results ───────────────────────────────────────────────────────────────────

results = {
    "engine": "pro" if args.pro else "free",
    "langs": args.langs or "none",
    "sensitivity": args.sensitivity,
    "files_scored": len(files),
    "errors_missing": errors,
    "TP": TP, "FP": FP, "TN": TN, "FN": FN,
    "precision": round(precision, 4),
    "recall": round(recall, 4),
    "f1": round(f1, 4),
    "fpr": round(fpr, 10),
    "fnr": round(fnr, 4),
    "accuracy": round(accuracy, 10),
    "elapsed_s": round(elapsed, 1),
}

print()
print("═" * 60)
print(f"  LocalMask ({results['engine']}) × CredData")
print("═" * 60)
print(f"  TP={TP}  FP={FP}  TN={TN}  FN={FN}")
print(f"  Precision : {precision:.4f}  ({precision*100:.1f}%)")
print(f"  Recall    : {recall:.4f}  ({recall*100:.1f}%)")
print(f"  F1        : {f1:.4f}  ({f1*100:.1f}%)")
print(f"  FPR       : {fpr:.8f}")
print(f"  FNR       : {fnr:.4f}")
print(f"  Accuracy  : {accuracy:.10f}")
print(f"  Time      : {elapsed:.1f}s  ({len(files)/elapsed:.0f} files/s)")
print()
print("  Published baselines (CredData 2022):")
print("  gitleaks      Recall 24.4%  Precision 52.6%  F1 33.4%")
print("  detect-secrets Recall 38.1%  Precision 14.2%  F1 20.6%")
print("  truffleHog3   Recall 54.7%  Precision 15.0%  F1 23.5%")
print("  CredSweeper   Recall 80.8%  Precision 91.7%  F1 85.9%")
print("═" * 60)

with open(args.out, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  Full results → {args.out}")
