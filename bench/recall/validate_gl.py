#!/usr/bin/env python3
"""Keep only the candidate strings gitleaks itself detects — self-validating
the ground-truth set on gitleaks' home turf. Writes gl_validated.json
(value -> gitleaks rule-id)."""
import json, os, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
cands = json.load(open(os.path.join(HERE, "cands.json")))

# Give each candidate keyword context (the rule name) so keyword-gated
# gitleaks rules can fire, then let gitleaks decide what's real.
lines = [f'{rid.replace("-", "_")}_secret = "{val}"' for val, rid in cands.items()]
open(os.path.join(HERE, "candidates.txt"), "w").write("\n".join(lines) + "\n")

out = os.path.join(HERE, "gl_cands.json")
subprocess.run(["gitleaks", "detect", "--source", HERE, "--no-git",
                "-f", "json", "-r", out, "--log-level", "error"],
               capture_output=True)
try:
    o = json.load(open(out))
except Exception:
    o = []
validated = {}
for d in o:
    validated[d.get("Secret")] = d.get("RuleID")
validated.pop(None, None)
json.dump(validated, open(os.path.join(HERE, "gl_validated.json"), "w"))
print(f"gitleaks validated {len(validated)} unique secrets "
      f"({len(set(validated.values()))} rule-types)")
