import re, os, glob, json
HERE = os.path.dirname(os.path.abspath(__file__))
# Point GITLEAKS_SRC at a clone of github.com/gitleaks/gitleaks
GL = os.environ.get("GITLEAKS_SRC", os.path.join(HERE, "gitleaks-src"))
RULES = os.path.join(GL, "cmd/generate/config/rules")
cands = {}   # value -> ruleid guess (from filename)
strlit = re.compile(r'"([^"\\]{12,})"')
for f in glob.glob(os.path.join(RULES, "*.go")):
    rid = os.path.basename(f)[:-3]
    txt = open(f, encoding="utf-8", errors="ignore").read()
    # only look inside the tps block(s)
    for m in strlit.finditer(txt):
        s = m.group(1)
        # skip obvious non-secrets: import paths, descriptions with spaces, urls-only
        if "/" in s and " " not in s and ("github.com" in s or "config" in s): continue
        if " " in s: continue
        if s.startswith("http") and "@" not in s and "key" not in s.lower(): continue
        if re.fullmatch(r'[a-zA-Z_]+', s): continue  # plain words
        cands.setdefault(s, rid)
json.dump(cands, open(os.path.join(HERE, "cands.json"), "w"))
print(f"candidate strings: {len(cands)}")
