#!/usr/bin/env python3
"""Run LocalMask / gitleaks / trufflehog on the recall corpus and score
recall against the ground-truth manifest (match by secret value)."""
import json, os, subprocess, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")
manifest = json.load(open(os.path.join(HERE, "manifest.json")))
planted = {m["value"] for m in manifest}
by_type = collections.defaultdict(set)
for m in manifest:
    by_type[m["type"]].add(m["value"])

# hard-negative values (any tool flagging one = FP)
HARD_NEG_VALS = {
    "your-api-key-here", "AKIAXXXXXXXXXXXXXXXX", "xxxxxxxxxxxxxxxxxxxxxxxx",
    "changeme", "REPLACE_WITH_YOUR_SECRET",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "550e8400-e29b-41d4-a716-446655440000",
    "sk-test-00000000000000000000",
    "5f4dcc3b5aa765d61d8327deb882cf99", "<INSERT_TOKEN>",
    "1234567890abcdef1234567890abcdef",
}

def norm(s):
    return (s or "").strip().strip('"').strip("'")

# ---- LocalMask (free edition) ----
# Scan every corpus file with the detection engine directly. (scan_repo()
# enumerates via git and would skip a non-git corpus dir — walking files is the
# faithful, deterministic path and matches how detection runs per-file.)
def run_localmask():
    os.environ["LOCALMASK_EDITION"] = "free"
    os.environ["OLLAMA_HOST"] = "http://127.0.0.1:1"
    sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))  # repo root
    import localmask.engine as E
    E._get_bert = lambda: None
    from localmask.engine import _scan_file
    from localmask.state import _new_session
    found = set()
    for root, _, files in os.walk(CORPUS):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                txt = open(fp, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            sess = _new_session(".", False)
            sess["sensitivity"] = "standard"
            for d in _scan_file(sess, txt, fn).get("findings", []):
                found.add(norm(d.get("value")))
    return found

# ---- gitleaks ----
def run_gitleaks():
    out = os.path.join(HERE, "gl_corpus.json")
    subprocess.run(["gitleaks", "detect", "--source", CORPUS, "--no-git",
                    "-f", "json", "-r", out, "--log-level", "error"],
                   capture_output=True)
    try:
        o = json.load(open(out))
    except Exception:
        o = []
    return {norm(d.get("Secret")) for d in o}

# ---- trufflehog ----
def run_trufflehog():
    p = subprocess.run(["trufflehog", "filesystem", CORPUS,
                        "--no-verification", "--json"],
                       capture_output=True, text=True)
    found = set()
    for ln in p.stdout.splitlines():
        try:
            d = json.loads(ln)
        except Exception:
            continue
        raw = d.get("Raw") or d.get("RawV2") or ""
        found.add(norm(raw))
        # trufflehog sometimes wraps; also try substring match later
    return found

def score(name, found):
    # A planted secret counts as recalled if its value appears in, or contains,
    # any detected string (tools sometimes trim/extend).
    hit = set()
    fjoined = found
    for v in planted:
        if v in fjoined or any(v in f or f in v for f in fjoined if f):
            hit.add(v)
    recall = len(hit) / len(planted) * 100
    fp = sum(1 for n in HARD_NEG_VALS if any(n == f or n in f for f in fjoined if f))
    return hit, recall, fp

def main():
    results = {}
    print("Running LocalMask...", flush=True)
    results["LocalMask (free)"] = run_localmask()
    print("Running gitleaks...", flush=True)
    results["gitleaks"] = run_gitleaks()
    print("Running trufflehog...", flush=True)
    results["trufflehog"] = run_trufflehog()

    print(f"\nGround truth: {len(planted)} planted secrets "
          f"({len(by_type)} gitleaks rule-types), gitleaks-validated.\n")
    print(f"{'tool':22s} {'recall':>8s} {'found':>7s} {'FP(hard-neg)':>13s}")
    scored = {}
    for name, found in results.items():
        hit, recall, fp = score(name, found)
        scored[name] = hit
        print(f"{name:22s} {recall:7.1f}% {len(hit):4d}/{len(planted):<3d} {fp:>10d}")

    # Per-type recall for LocalMask (where do we miss?)
    lm = scored["LocalMask (free)"]
    print("\nLocalMask per-type recall (gitleaks rule-id):")
    misses = []
    for t, vals in sorted(by_type.items()):
        got = len(vals & lm)
        if got < len(vals):
            misses.append((t, got, len(vals)))
    if not misses:
        print("  (no misses — 100% on every type)")
    for t, got, tot in sorted(misses, key=lambda x: x[1]-x[2]):
        print(f"  MISS {t:32s} {got}/{tot}")
    json.dump({k: sorted(v) for k, v in scored.items()},
              open(os.path.join(HERE, "scored.json"), "w"))

if __name__ == "__main__":
    main()
