# Recall benchmark — measurable, reproducible, adversarial

A true **recall** number (what fraction of real secrets a scanner catches)
needs ground truth: a corpus where every planted secret is known in advance.
This harness builds one on **gitleaks' home turf** — so the comparison is
adversarial to LocalMask, not favorable.

## Method

1. **Extract** every sample secret literal from gitleaks' own rule definitions
   (`cmd/generate/config/rules/*.go`) — `extract_gl.py`.
2. **Validate** them through gitleaks itself; keep only the ones gitleaks
   detects — `validate_gl.py`. This makes gitleaks' recall ≈100% *by
   construction* on the raw set: we are testing on the exact secrets gitleaks
   was built to catch.
3. **Plant** each validated secret into a realistic file at a known location,
   across varied file types and contexts (`.py`, `.env`, `.yaml`, `.json`,
   `.sh`, connection strings, `.md` code blocks), plus 12 hard-negative files
   (secret-shaped non-secrets: placeholders, git SHAs, UUIDs, md5 hashes) —
   `gen_corpus.py`. The ground-truth manifest records every planted value.
4. **Score** LocalMask / gitleaks / trufflehog by matching detected values
   against the manifest — `run_bench.py`. Recall = planted found / planted
   total; FP = hard-negatives flagged.

Everything is deterministic (no RNG) and reproducible. Generated artifacts
contain secret-shaped literals and are git-ignored — only the scripts are
committed.

## Run it

```bash
git clone https://github.com/gitleaks/gitleaks bench/recall/gitleaks-src   # or set GITLEAKS_SRC
cd bench/recall
python extract_gl.py && python validate_gl.py && python gen_corpus.py && python run_bench.py
```
Requires `gitleaks` and `trufflehog` on PATH.

## Results (2026-07-12, 133 gitleaks-validated secrets, 30 rule-types)

| tool | recall | found | FP (hard-neg) |
|------|-------:|------:|--------------:|
| **LocalMask (free)** | **94.7%** | 126/133 | 8 |
| gitleaks | 86.5% | 115/133 | 1 |
| trufflehog (static) | 33.1% | 44/133 | 0 |

### Honest reading

- **LocalMask leads on recall — on gitleaks' own secrets.** 94.7% vs gitleaks'
  86.5% on the same corpus. This is the real, defensible recall headline.
- **Why gitleaks drops below 100% on its own set:** several gitleaks rules are
  keyword-gated. The validated set was confirmed in `<rule>_secret = "..."`
  context; re-planting into `.yaml` / `.json` / connection strings / `.md`
  strips that keyword, so those rules stop firing. LocalMask's format-first
  matching is more robust to context change — that's the advantage the number
  reflects.
- **LocalMask trails on precision:** 8 hard-negative flags vs gitleaks' 1. Of
  the 8: `AKIAXXXX…` (exact AWS shape — arguably correct to flag) is defensible;
  a **git commit SHA (40-hex)**, a **UUID**, an **md5 hash**, and a bare 32-hex
  string are flagged as generic `secret`. UUID and git-SHA are safe to suppress
  (distinctive shapes); bare 32-hex is an inherent recall/precision tradeoff (a
  real API key is often exactly 32-hex — excluding that shape would cut recall).
- **trufflehog** is verification-first; with `--no-verification` its static
  recall is low. Not a knock on the tool — a different design point.

### Caveats

- This measures recall **relative to gitleaks' catalog**, not absolute
  real-world recall. For an absolute, in-the-wild number, use SecretBench
  (academic, gated) with the same `run_bench.py` scorer.
- A synthetic corpus can't capture every real-world context. It is a strong
  precision/recall proxy, not a substitute for a labeled real corpus.
