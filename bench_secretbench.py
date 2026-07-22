#!/usr/bin/env python3
"""
LocalMask × SecretBench benchmark runner
=========================================
Scores LocalMask against SecretBench (MSR 2023 — arxiv:2303.06729).
97,479 manually labeled secrets from 818 real GitHub repos, 49 languages.

DATASET ACCESS (required first)
--------------------------------
SecretBench data is in Google BigQuery + Cloud Storage behind a data
protection agreement. Steps to get it:

1. Email the authors (setu1421@gmail.com) to sign the data agreement.
   Reference: https://github.com/setu1421/SecretBench

2. Once approved, export the BigQuery table to CSV:
   Project: dev-range-332204  Dataset: secretbench  Table: secrets

   In BigQuery console:
     SELECT * FROM `dev-range-332204.secretbench.secrets`
   → Export → CSV → download as secrets.csv

3. Download files from Cloud Storage (bucket: secretbench, file: Files.zip).
   Extract to a local directory (FILES_DIR below).

4. Set env vars:
   export SECRETBENCH_CSV=/path/to/secrets.csv
   export SECRETBENCH_FILES=/path/to/extracted/files

5. Run:
   python bench_secretbench.py [--pro] [--limit N]

CSV schema (key fields)
-----------------------
id, secret, repo_name, file_path, start_line, end_line, label (True/False),
is_template, in_url, entropy, character_set, has_words, length,
is_multiline, category, file_identifier, repo_identifier, comment

How it works
------------
Same methodology as bench_creddata.py:
1. Read ground truth: file_path + start_line + label (True/False)
2. Run LocalMask regex on each labeled file
3. Check if LocalMask flagged the exact line
4. Compute TP/FP/TN/FN/Precision/Recall/F1
"""

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

# ── CLI args ──────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="LocalMask × SecretBench benchmark")
parser.add_argument("--pro", action="store_true", help="Use Pro engine (LLM classifier)")
parser.add_argument("--limit", type=int, default=0, help="Limit to first N labeled files")
parser.add_argument("--sensitivity", default="standard",
                    choices=["minimal", "standard", "strict"])
parser.add_argument("--out", default="secretbench_results.json")
parser.add_argument("--csv",
                    default=os.environ.get("SECRETBENCH_CSV", "secrets.csv"),
                    help="Path to BigQuery CSV export of secrets table")
parser.add_argument("--files-dir",
                    default=os.environ.get("SECRETBENCH_FILES", "/tmp/SecretBench/files"),
                    help="Path to extracted Files.zip from Cloud Storage")
args = parser.parse_args()

# ── Check inputs ──────────────────────────────────────────────────────────────

if not os.path.exists(args.csv):
    print(f"""
ERROR: SecretBench CSV not found: {args.csv}

SecretBench data requires a data protection agreement. Steps:
1. Email setu1421@gmail.com to sign the agreement.
2. Export BigQuery table dev-range-332204.secretbench.secrets to CSV.
3. Download Files.zip from Cloud Storage bucket 'secretbench'.
4. Run:  SECRETBENCH_CSV=/path/to/secrets.csv SECRETBENCH_FILES=/path/to/files \\
         python bench_secretbench.py

See: https://github.com/setu1421/SecretBench
""")
    sys.exit(1)

if not os.path.isdir(args.files_dir):
    sys.exit(f"ERROR: Files directory not found: {args.files_dir}\n"
             "Download Files.zip from bucket 'secretbench' and extract it.")

# ── Engine setup ──────────────────────────────────────────────────────────────

if args.pro:
    os.environ["LOCALMASK_EDITION"] = "pro"
    os.environ["LOCALMASK_ACCEPT_LEGACY_KEYS"] = "1"
else:
    os.environ.setdefault("LOCALMASK_EDITION", "free")
    os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"  # disable LLM for free

from regex_rules_safe import RegexRulesSafe  # noqa: E402

# ── Load ground truth ─────────────────────────────────────────────────────────
# Group by (file_identifier, file_path) → {line_num: is_real}
# SecretBench CSV uses start_line (int) and label ("True"/"False" boolean as string)

print(f"Loading SecretBench ground truth from {args.csv} ...")

# ground_truth[abs_file_path] = {line_num: bool}
ground_truth: dict[str, dict[int, bool]] = {}
# Also track category for per-category breakdown
line_category: dict[str, dict[int, str]] = {}

SECRETBENCH_FILES = Path(args.files_dir)

total_rows = 0
skipped_template = 0

with open(args.csv, newline="", encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        total_rows += 1
        file_id   = row.get("file_identifier", "").strip()
        file_path = row.get("file_path", "").strip()
        try:
            line = int(row.get("start_line", 0))
        except (ValueError, TypeError):
            continue
        if not line:
            continue

        # label column is boolean: "True" or "False"
        label_raw = row.get("label", "false").strip().lower()
        is_real = label_raw in ("true", "1", "yes")

        # SecretBench stores files as: {files_dir}/{file_identifier}{ext}
        # The file_identifier is a hash; file_path gives the extension.
        ext = os.path.splitext(file_path)[1]
        abs_path = str(SECRETBENCH_FILES / f"{file_id}{ext}") if file_id else ""
        if not abs_path:
            continue

        ground_truth.setdefault(abs_path, {})[line] = is_real
        line_category.setdefault(abs_path, {})[line] = row.get("category", "Unknown").strip()

total_labeled_files = len(ground_truth)
total_labeled_lines = sum(len(v) for v in ground_truth.values())
total_true  = sum(sum(1 for v in d.values() if v)     for d in ground_truth.values())
total_false = sum(sum(1 for v in d.values() if not v)  for d in ground_truth.values())

print(f"  Rows in CSV    : {total_rows:,}")
print(f"  Labeled files  : {total_labeled_files:,}")
print(f"  Labeled lines  : {total_labeled_lines:,}  ({total_true:,} True / {total_false:,} False)")

# ── Scan and score ────────────────────────────────────────────────────────────

files = list(ground_truth.keys())
if args.limit:
    files = files[: args.limit]
    print(f"  (limiting to first {args.limit} files)")

TP = FP = FN = 0
errors = 0
category_stats: dict[str, dict[str, int]] = {}
t0 = time.time()

for i, fpath in enumerate(files, 1):
    if i % 500 == 0 or i == 1:
        elapsed = time.time() - t0
        rate = i / max(elapsed, 0.001)
        remaining = (len(files) - i) / max(rate, 0.001)
        prec = TP / (TP + FP) if (TP + FP) else 0
        rec  = TP / (TP + FN) if (TP + FN) else 0
        print(f"  [{i:,}/{len(files):,}]  TP={TP} FP={FP} FN={FN}  "
              f"P={prec:.2f} R={rec:.2f}  "
              f"({rate:.0f} files/s  ~{remaining:.0f}s left)")

    gt_lines = ground_truth[fpath]

    if not os.path.exists(fpath):
        FN += sum(1 for v in gt_lines.values() if v)
        errors += 1
        continue

    try:
        content = open(fpath, errors="ignore").read()
    except OSError:
        FN += sum(1 for v in gt_lines.values() if v)
        errors += 1
        continue

    detections = RegexRulesSafe.scan_file(fpath, content, args.sensitivity)
    detected_lines = {d["line"] for d in detections}

    cats = line_category.get(fpath, {})

    for line_num, is_real in gt_lines.items():
        flagged = line_num in detected_lines
        cat = cats.get(line_num, "Unknown")
        cs = category_stats.setdefault(cat, {"TP": 0, "FP": 0, "FN": 0})

        if is_real and flagged:
            TP += 1
            cs["TP"] += 1
        elif not is_real and flagged:
            FP += 1
            cs["FP"] += 1
        elif is_real and not flagged:
            FN += 1
            cs["FN"] += 1

elapsed = time.time() - t0

scanned_false = sum(sum(1 for v in ground_truth[f].values() if not v)
                    for f in files)
TN = scanned_false - FP

precision = TP / (TP + FP)  if (TP + FP)  else 0.0
recall    = TP / (TP + FN)  if (TP + FN)  else 0.0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
fpr       = FP / (FP + TN)  if (FP + TN)  else 0.0

# ── Results ───────────────────────────────────────────────────────────────────

print()
print("═" * 68)
print(f"  LocalMask ({('pro' if args.pro else 'free')}, sensitivity={args.sensitivity}) × SecretBench")
print("═" * 68)
print(f"  TP={TP}  FP={FP}  TN={TN}  FN={FN}  (missing={errors})")
print(f"  Precision : {precision*100:5.1f}%")
print(f"  Recall    : {recall*100:5.1f}%")
print(f"  F1        : {f1*100:5.1f}%")
print(f"  Time      : {elapsed:.1f}s  ({len(files)/elapsed:.0f} files/s)")
print()
print("  Per-category breakdown:")
print(f"  {'Category':<35}  {'TP':>6}  {'FP':>6}  {'FN':>6}  {'Prec':>6}  {'Rec':>6}")
for cat, cs in sorted(category_stats.items()):
    p = cs['TP'] / (cs['TP'] + cs['FP']) if (cs['TP'] + cs['FP']) else 0
    r = cs['TP'] / (cs['TP'] + cs['FN']) if (cs['TP'] + cs['FN']) else 0
    print(f"  {cat:<35}  {cs['TP']:>6}  {cs['FP']:>6}  {cs['FN']:>6}  {p*100:>5.1f}%  {r*100:>5.1f}%")
print()
print("  Published baselines (full SecretBench, 9 tools):")
print("  ┌──────────────────────┬──────────┬───────────┬───────┐")
print("  │ Tool                 │ Recall   │ Precision │ F1    │")
print("  ├──────────────────────┼──────────┼───────────┼───────┤")
print("  │ gitleaks             │   8.9%   │   74.6%   │ 15.9% │")
print("  │ detect-secrets       │  11.8%   │   58.3%   │ 19.6% │")
print("  │ truffleHog           │  58.2%   │   69.9%   │ 63.5% │")
print("  │ CredSweeper          │  58.7%   │   90.8%   │ 71.3% │")
print(f"  │ LocalMask ({('pro' if args.pro else 'free'):4})      │ {recall*100:5.1f}%   │  {precision*100:5.1f}%   │{f1*100:5.1f}% │")
print("  └──────────────────────┴──────────┴───────────┴───────┘")
print("═" * 68)

results = {
    "engine": "pro" if args.pro else "free",
    "sensitivity": args.sensitivity,
    "files_scored": len(files),
    "errors_missing": errors,
    "TP": TP, "FP": FP, "TN": TN, "FN": FN,
    "precision": round(precision, 4),
    "recall":    round(recall, 4),
    "f1":        round(f1, 4),
    "fpr":       round(fpr, 4),
    "elapsed_s": round(elapsed, 1),
    "per_category": category_stats,
}

with open(args.out, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  Full results → {args.out}")
