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

   macOS note: patch download_and_check to warn+return instead of re-raise
   so repos that don't support SHA fetch are skipped gracefully.

2. Set CREDDATA_DIR to the path of the cloned + downloaded repo:
   export CREDDATA_DIR=/tmp/CredData

3. Run:
   cd /path/to/localmask-oss
   python bench_creddata.py [--pro] [--langs he] [--limit N]

   --pro      Use the Pro engine (LOCALMASK_ACCEPT_LEGACY_KEYS=1 + LOCALMASK_EDITION=pro).
   --langs    LOCALMASK_LANGS value (default: none). Use "he" for Hebrew PII.
   --limit N  Only score the first N labeled files (useful for a quick smoke test).
   --out FILE Write JSON results to FILE (default: creddata_results.json).

How it works
------------
CredData's meta/*.csv files label every suspicious line as T (real credential)
or F (placeholder/test data). This script:

1. Reads ground-truth labels (file path + line number + T/F) from meta/*.csv.
2. Runs LocalMask's regex scanner on each labeled file.
3. For each labeled line checks whether LocalMask flagged that exact line.
4. Computes TP/FP/TN/FN and derives Precision/Recall/F1.

Scoring matches CredData's published benchmark: a detection is TP if LocalMask
flags any credential on the same line number as a ground-truth T label.
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
parser.add_argument("--comment-scanner", action="store_true",
                    help="Also run CommentScanner (Pro only) to find credentials in comments")
args = parser.parse_args()

CREDDATA_DIR = Path(args.creddata_dir)
META_DIR = CREDDATA_DIR / "meta"

if not CREDDATA_DIR.exists():
    sys.exit(f"ERROR: CredData dir not found: {CREDDATA_DIR}\n"
             f"Clone it and run download_data.py first — see docstring above.")
if not META_DIR.exists():
    sys.exit(f"ERROR: {META_DIR} not found — make sure you cloned the full CredData repo.")

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

# For Pro mode, also load the sensitivity classifier so the LLM layer runs.
# This mirrors what engine.py does: regex detections that pass the classifier
# are kept; those the LLM marks NOT_SENSITIVE are dropped (improving Precision).
_clf = None
if args.pro:
    try:
        # sensitivity_classifier.py lives in the Pro repo (files11_mcp).
        # Try several locations: same dir as this script, Pro repo sibling, or PATH.
        _here = os.path.dirname(os.path.abspath(__file__))
        _pro_candidates = [
            _here,
            os.path.join(_here, "..", "files11_mcp"),
            os.path.join(_here, "..", "localmask-pro"),
            os.environ.get("LOCALMASK_PRO_DIR", ""),
        ]
        for _p in _pro_candidates:
            if _p and os.path.exists(os.path.join(_p, "sensitivity_classifier.py")):
                sys.path.insert(0, os.path.abspath(_p))
                break
        from sensitivity_classifier import SensitivityClassifier
        _clf = SensitivityClassifier()
        print(f"  Pro LLM classifier loaded — "
              f"learned: {len(_clf._feedback_rules)}, "
              f"embeddings: {len(_clf._emb_index)}")
    except Exception as e:
        print(f"  WARNING: could not load classifier ({e}) — running regex-only")

# ── CommentScanner (Pro + --comment-scanner) ──────────────────────────────────
_cs = None
if args.pro and args.comment_scanner:
    try:
        _here = os.path.dirname(os.path.abspath(__file__))
        for _p in [_here, os.path.join(_here, "..", "files11_mcp"),
                   os.environ.get("LOCALMASK_PRO_DIR", "")]:
            if _p and os.path.exists(os.path.join(_p, "comment_scanner.py")):
                sys.path.insert(0, os.path.abspath(_p))
                break
        from comment_scanner import CommentScanner
        _cs = CommentScanner()
        print("  CommentScanner loaded — will scan comment blocks for missed credentials")
    except Exception as e:
        print(f"  WARNING: CommentScanner not available ({e})")


def _apply_llm_gate(detections: list, file_path: str) -> list:
    """Run detections through the Pro LLM classifier; drop NOT_SENSITIVE ones."""
    if not _clf or not detections:
        return detections
    rel = os.path.relpath(file_path, str(CREDDATA_DIR)) if CREDDATA_DIR else file_path
    batch = [
        {
            "entity":    d["entity"],
            "context":   (f"[{rel}] " + d.get("context", ""))[:200],
            "file_type": d.get("file_type", ""),
            "ner_label": d.get("ner_label", d.get("type", "")),
        }
        for d in detections
    ]
    try:
        results = _clf.classify_batch(batch)
    except Exception:
        return detections
    kept = []
    for det, res in zip(detections, results):
        if res and res.get("decision") == "NOT_SENSITIVE":
            continue
        kept.append(det)
    return kept

# ── Load CredData ground truth ────────────────────────────────────────────────
# meta/*.csv columns: Id, FileID, Domain, RepoName, FilePath, LineStart, LineEnd,
#                     GroundTruth (T/F), ValueStart, ValueEnd, CryptographyKey,
#                     PredefinedPattern, Category
# FilePath is relative to CREDDATA_DIR, e.g. "data/00408ef6/sample/1d02852d.c"

print(f"Loading CredData ground truth from {META_DIR} ...")

# ground_truth[abs_file_path] = {line_num: bool}  (True = real credential)
ground_truth: dict[str, dict[int, bool]] = {}

for csv_path in sorted(META_DIR.glob("*.csv")):
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            rel = row.get("FilePath", "").strip()
            if not rel:
                continue
            try:
                line = int(row.get("LineStart", 0))
            except ValueError:
                continue
            is_real = row.get("GroundTruth", "F").strip().upper() == "T"
            abs_path = str(CREDDATA_DIR / rel)
            ground_truth.setdefault(abs_path, {})[line] = is_real

total_labeled_files = len(ground_truth)
total_labeled_lines = sum(len(v) for v in ground_truth.values())
total_true  = sum(sum(1 for v in d.values() if v)     for d in ground_truth.values())
total_false = sum(sum(1 for v in d.values() if not v)  for d in ground_truth.values())

print(f"  {total_labeled_files:,} labeled files")
print(f"  {total_labeled_lines:,} labeled lines  "
      f"({total_true:,} True / {total_false:,} False)")

# ── Scan and score ────────────────────────────────────────────────────────────

files = list(ground_truth.keys())
if args.limit:
    files = files[:args.limit]
    print(f"  (limiting to first {args.limit} files)")

TP = FP = FN = 0
errors = 0
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
    if args.pro:
        detections = _apply_llm_gate(detections, fpath)
    if _cs:
        existing = {d["entity"] for d in detections}
        for hit in _cs.scan_file(content, fpath):
            if hit["entity"] not in existing:
                detections.append(hit)
                existing.add(hit["entity"])
    detected_lines = {d["line"] for d in detections}

    for line_num, is_real in gt_lines.items():
        flagged = line_num in detected_lines
        if is_real and flagged:
            TP += 1
        elif not is_real and flagged:
            FP += 1
        elif is_real and not flagged:
            FN += 1
        # TN: not real and not flagged — counted below

elapsed = time.time() - t0

# TN = labeled-False lines that were NOT flagged
scanned_false = sum(sum(1 for v in ground_truth[f].values() if not v)
                    for f in files)
TN = scanned_false - FP

precision = TP / (TP + FP)  if (TP + FP)  else 0.0
recall    = TP / (TP + FN)  if (TP + FN)  else 0.0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
fpr       = FP / (FP + TN)  if (FP + TN)  else 0.0
fnr       = FN / (FN + TP)  if (FN + TP)  else 0.0
accuracy  = (TP + TN) / (TP + FP + TN + FN) if (TP + FP + TN + FN) else 0.0

# ── Results ───────────────────────────────────────────────────────────────────

results = {
    "engine": ("pro+comments" if (args.pro and args.comment_scanner) else
               "pro" if args.pro else "free"),
    "langs": args.langs or "none",
    "sensitivity": args.sensitivity,
    "files_scored": len(files),
    "errors_missing": errors,
    "TP": TP, "FP": FP, "TN": TN, "FN": FN,
    "precision": round(precision, 4),
    "recall":    round(recall, 4),
    "f1":        round(f1, 4),
    "fpr":       round(fpr, 10),
    "fnr":       round(fnr, 4),
    "accuracy":  round(accuracy, 10),
    "elapsed_s": round(elapsed, 1),
}

print()
print("═" * 64)
print(f"  LocalMask ({results['engine']}, sensitivity={args.sensitivity}) × CredData")
print("═" * 64)
print(f"  TP={TP}  FP={FP}  TN={TN}  FN={FN}  (missing={errors})")
print(f"  Precision : {precision*100:5.1f}%")
print(f"  Recall    : {recall*100:5.1f}%")
print(f"  F1        : {f1*100:5.1f}%")
print(f"  FPR       : {fpr:.8f}")
print(f"  FNR       : {fnr:.4f}")
print(f"  Accuracy  : {accuracy:.8f}")
print(f"  Time      : {elapsed:.1f}s  ({len(files)/elapsed:.0f} files/s)")
print()
print("  Published baselines on full CredData (2022):")
print("  ┌──────────────────┬──────────┬───────────┬───────┐")
print("  │ Tool             │ Recall   │ Precision │ F1    │")
print("  ├──────────────────┼──────────┼───────────┼───────┤")
print("  │ gitleaks         │  24.4%   │   52.6%   │ 33.4% │")
print("  │ detect-secrets   │  38.1%   │   14.2%   │ 20.6% │")
print("  │ truffleHog3      │  54.7%   │   15.0%   │ 23.5% │")
print("  │ CredSweeper      │  80.8%   │   91.7%   │ 85.9% │")
print(f"  │ LocalMask ({results['engine']:4s})  │ {recall*100:5.1f}%   │  {precision*100:5.1f}%   │{f1*100:5.1f}% │")
print("  └──────────────────┴──────────┴───────────┴───────┘")
print("═" * 64)

with open(args.out, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  Full results → {args.out}")
