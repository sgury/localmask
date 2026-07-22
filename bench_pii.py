#!/usr/bin/env python3
"""
LocalMask × ai4privacy/pii-masking-400k PII benchmark
======================================================
Scores LocalMask against the AI4Privacy dataset — 400K text samples
with 55 PII types labeled at token level (character offsets). Free on HuggingFace.

Prerequisites
-------------
    pip install datasets

Run (first run auto-downloads ~500MB, cached after):
    python bench_pii.py [--split validation] [--limit 2000] [--pro]

    --split     train / validation / test  (default: validation)
    --limit N   score first N samples (0 = all 81K validation samples)
    --pro       use Pro engine (Ollama LLM classifier)
    --out FILE  output JSON (default: pii_results.json)
"""

import argparse
import json
import os
import re
import sys
import time

# ── CLI ───────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser()
parser.add_argument("--pro", action="store_true")
parser.add_argument("--split", default="validation",
                    choices=["train", "validation", "test"])
parser.add_argument("--limit", type=int, default=2000)
parser.add_argument("--sensitivity", default="standard",
                    choices=["minimal", "standard", "strict"])
parser.add_argument("--out", default="pii_results.json")
args = parser.parse_args()

# ── Import datasets ───────────────────────────────────────────────────────────

try:
    from datasets import load_dataset
except ImportError:
    sys.exit("ERROR: pip install datasets")

# ── Engine setup ──────────────────────────────────────────────────────────────

if args.pro:
    os.environ["LOCALMASK_EDITION"] = "pro"
    os.environ["LOCALMASK_ACCEPT_LEGACY_KEYS"] = "1"
else:
    os.environ.setdefault("LOCALMASK_EDITION", "free")
    os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"

from regex_rules_safe import RegexRulesSafe  # noqa: E402

# ── Actual ai4privacy label names (verified from dataset) ────────────────────
# Map ai4privacy label → category group that LocalMask covers
COVERED_BY_LOCALMASK = {
    # Email
    "EMAIL":            "email",
    # Phone
    "TELEPHONENUM":     "phone",
    # Financial
    "CREDITCARDNUMBER": "financial",
    "CREDITCARDCVV":    "financial",
    "CREDITCARDISSUER": "financial",
    "IBAN":             "financial",
    # ID numbers (SSN-like)
    "SOCIALNUM":        "id_doc",
    "IDCARDNUM":        "id_doc",
    "DRIVERLICENSENUM": "id_doc",
    "TAXNUM":           "id_doc",
    "PASSPORTNUM":      "id_doc",
    # Network
    "IPV4":             "network",
    "IPV6":             "network",
    "IPADDRESS":        "network",
    "URL":              "network",
    # Passwords / secrets
    "PASSWORD":         "secret",
    "ACCOUNTNUM":       "financial",
}

# ── Load dataset ──────────────────────────────────────────────────────────────

print(f"Loading ai4privacy/pii-masking-400k [{args.split}] ...")
ds = load_dataset("ai4privacy/pii-masking-400k", split=args.split)

total_samples = len(ds)
samples = ds if not args.limit else ds.select(range(min(args.limit, total_samples)))
print(f"  {total_samples:,} total; scoring {len(samples):,}")

# ── Scan and score ────────────────────────────────────────────────────────────

TP = FP = FN = 0
category_stats: dict[str, dict[str, int]] = {}
t0 = time.time()

ANSI_STRIP = re.compile(r'\x1b\[[0-9;]*m')


def _char_spans_from_detections(text: str, detections: list) -> list[tuple[int,int,str]]:
    """Convert line-based detections to character spans in text."""
    # Precompute line start offsets
    line_starts = [0]
    for ch in text:
        if ch == "\n":
            line_starts.append(line_starts[-1] + 1)
        else:
            line_starts[-1] += 1
    # Rebuild as cumulative offsets
    offsets = [0]
    for line in text.split("\n"):
        offsets.append(offsets[-1] + len(line) + 1)   # +1 for \n

    spans = []
    for det in detections:
        line_no = det["line"]  # 1-based
        ent = det["entity"]
        if line_no <= 0 or line_no > len(offsets) - 1:
            continue
        line_start_char = offsets[line_no - 1]
        # Find entity within the line
        line_text = text.split("\n")[line_no - 1] if line_no - 1 < len(text.split("\n")) else ""
        pos = line_text.find(ent)
        if pos < 0:
            # fallback: search whole text (handles wrap)
            pos = text.find(ent)
            if pos < 0:
                continue
            spans.append((pos, pos + len(ent), det["type"]))
        else:
            abs_pos = line_start_char + pos
            spans.append((abs_pos, abs_pos + len(ent), det["type"]))
    return spans


def _overlap(a0, a1, b0, b1) -> bool:
    return a0 < b1 and b0 < a1


for i, sample in enumerate(samples):
    if i % 500 == 0:
        elapsed = time.time() - t0
        rate = max(i, 1) / max(elapsed, 0.001)
        remaining = (len(samples) - i) / rate
        prec = TP / (TP + FP) if (TP + FP) else 0
        rec  = TP / (TP + FN) if (TP + FN) else 0
        print(f"  [{i:,}/{len(samples):,}]  TP={TP} FP={FP} FN={FN}  "
              f"P={prec:.2f} R={rec:.2f}  (~{remaining:.0f}s left)")

    text  = sample.get("source_text", "") or ""
    masks = sample.get("privacy_mask", []) or []

    if not text:
        continue

    # Labeled spans we expect LocalMask to cover
    labeled: list[tuple[int,int,str,str]] = []   # (start, end, label, group)
    for m in masks:
        lbl = m.get("label", "")
        if lbl in COVERED_BY_LOCALMASK:
            start = m.get("start", -1)
            end   = m.get("end",   -1)
            if start >= 0 and end > start:
                labeled.append((start, end, lbl, COVERED_BY_LOCALMASK[lbl]))

    # Run LocalMask regex
    dets = RegexRulesSafe.scan_file("sample.txt", text, args.sensitivity)
    det_spans = _char_spans_from_detections(text, dets)

    # Match detections → labeled spans
    matched_labels: set[int] = set()
    for d_start, d_end, d_type in det_spans:
        matched = any(
            _overlap(d_start, d_end, l_start, l_end)
            for l_start, l_end, _, _ in labeled
        )
        if matched:
            TP += 1
            for j, (l_start, l_end, lbl, group) in enumerate(labeled):
                if _overlap(d_start, d_end, l_start, l_end):
                    matched_labels.add(j)
                    category_stats.setdefault(group, {"TP": 0, "FP": 0, "FN": 0})["TP"] += 1
        else:
            FP += 1

    for j, (l_start, l_end, lbl, group) in enumerate(labeled):
        if j not in matched_labels:
            FN += 1
            category_stats.setdefault(group, {"TP": 0, "FP": 0, "FN": 0})["FN"] += 1

elapsed = time.time() - t0

precision = TP / (TP + FP)  if (TP + FP)  else 0.0
recall    = TP / (TP + FN)  if (TP + FN)  else 0.0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

# ── Results ───────────────────────────────────────────────────────────────────

print()
print("═" * 68)
print(f"  LocalMask ({('pro' if args.pro else 'free')}) × AI4Privacy PII Benchmark")
print("═" * 68)
print(f"  Samples: {len(samples):,}  split={args.split}  sensitivity={args.sensitivity}")
print(f"  Covered PII types ({len(COVERED_BY_LOCALMASK)}): "
      f"{', '.join(sorted(COVERED_BY_LOCALMASK))}")
print(f"  TP={TP}  FP={FP}  FN={FN}")
print(f"  Precision : {precision*100:5.1f}%")
print(f"  Recall    : {recall*100:5.1f}%")
print(f"  F1        : {f1*100:5.1f}%")
print(f"  Time      : {elapsed:.1f}s  ({len(samples)/elapsed:.0f} samples/s)")
print()
print("  Per-category breakdown:")
print(f"  {'Category':<12}  {'TP':>6}  {'FP':>6}  {'FN':>6}  {'Prec':>6}  {'Rec':>6}")
for cat, cs in sorted(category_stats.items()):
    p = cs['TP'] / (cs['TP'] + cs['FP']) if (cs['TP'] + cs['FP']) else 0
    r = cs['TP'] / (cs['TP'] + cs['FN']) if (cs['TP'] + cs['FN']) else 0
    print(f"  {cat:<12}  {cs['TP']:>6}  {cs['FP']:>6}  {cs['FN']:>6}  {p*100:>5.1f}%  {r*100:>5.1f}%")
print()
print("  Note: ai4privacy has 55 PII types total. LocalMask covers structural")
print("  PII (emails, phones, cards, SSNs, IPs) — not names/addresses/dates")
print("  which require NER. Those are covered by the Pro LLM layer.")
print("═" * 68)

results = {
    "engine":     "pro" if args.pro else "free",
    "dataset":    "ai4privacy/pii-masking-400k",
    "split":      args.split,
    "sensitivity": args.sensitivity,
    "samples_scored": len(samples),
    "covered_pii_types": sorted(COVERED_BY_LOCALMASK),
    "TP": TP, "FP": FP, "FN": FN,
    "precision":  round(precision, 4),
    "recall":     round(recall, 4),
    "f1":         round(f1, 4),
    "elapsed_s":  round(elapsed, 1),
    "per_category": category_stats,
}

with open(args.out, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  Full results → {args.out}")
