#!/usr/bin/env python3
"""Build a ground-truth recall corpus from gitleaks-validated secrets.

Plants each validated secret into a realistic file at a KNOWN location (the
ground truth), across varied file types and contexts, and mixes in hard
negatives (secret-shaped non-secrets) so precision is measurable too.
"""
import json, os, hashlib, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "corpus")
gl = json.load(open(os.path.join(HERE, "gl_validated.json")))   # value -> ruleid
secrets = list(gl.items())

# Deterministic pseudo-shuffle (no random — reproducible)
secrets.sort(key=lambda kv: hashlib.sha256(kv[0].encode()).hexdigest())

if os.path.isdir(OUT):
    shutil.rmtree(OUT)
os.makedirs(OUT)

manifest = []   # {file, line, value, type, planted}

# Context templates: (extension, render(fn(varname, value)) -> list of lines)
# Each returns (lines, secret_line_index_0based) so we know where the secret sits.
def t_py(var, val):
    return ([f"# service configuration",
             f"import os",
             f"{var} = \"{val}\"",
             f"client = connect({var})"], 2)
def t_env(var, val):
    return ([f"# .env — do not commit",
            f"{var.upper()}={val}",
            f"LOG_LEVEL=info"], 1)
def t_yaml(var, val):
    return ([f"service:",
            f"  region: us-east-1",
            f"  {var}: {val}"], 2)
def t_json(var, val):
    return ("{\n"
            f"  \"{var}\": \"{val}\",\n"
            "  \"timeout\": 30\n"
            "}").split("\n"), 1
def t_sh(var, val):
    return ([f"#!/bin/bash",
            f"export {var.upper()}=\"{val}\"",
            f"curl -H \"Authorization: Bearer ${var.upper()}\" $API"], 1)
def t_conn(var, val):
    return ([f"# connection string",
            f"DATABASE_URL = \"postgres://admin:{val}@db.internal:5432/prod\""], 1)
def t_md(var, val):
    return ([f"## Setup",
            f"Set your credential:",
            f"```",
            f"{var}={val}",
            f"```"], 3)

TEMPLATES = [t_py, t_env, t_yaml, t_json, t_sh, t_conn, t_md]
EXT = {"t_py": "py", "t_env": "env", "t_yaml": "yaml", "t_json": "json",
       "t_sh": "sh", "t_conn": "cfg", "t_md": "md"}

# spread secrets across ~30 repos
NREPOS = 30
for idx, (val, rid) in enumerate(secrets):
    repo = f"repo-{idx % NREPOS:02d}"
    tmpl = TEMPLATES[idx % len(TEMPLATES)]
    var = rid.replace("-", "_")
    lines, sidx = tmpl(var, val)
    ext = EXT[tmpl.__name__]
    fname = "config.env" if ext == "env" else f"svc_{idx}.{ext}"
    rdir = os.path.join(OUT, repo)
    os.makedirs(rdir, exist_ok=True)
    fpath = os.path.join(rdir, fname)
    with open(fpath, "w") as f:
        f.write("\n".join(lines) + "\n")
    manifest.append({"file": os.path.relpath(fpath, OUT),
                     "line": sidx + 1, "value": val, "type": rid,
                     "planted": True})

# Hard negatives — secret-shaped NON-secrets, spread across repos.
HARD_NEG = [
    'API_KEY = "your-api-key-here"',
    'AWS_ACCESS_KEY_ID = "AKIAXXXXXXXXXXXXXXXX"',
    'token = "xxxxxxxxxxxxxxxxxxxxxxxx"',
    'password = "changeme"',
    'secret = "REPLACE_WITH_YOUR_SECRET"',
    'commit = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"',  # git sha
    'uuid = "550e8400-e29b-41d4-a716-446655440000"',
    'sk_example = "sk-test-00000000000000000000"',
    'hash = "5f4dcc3b5aa765d61d8327deb882cf99"',            # md5 of "password"
    'placeholder = "<INSERT_TOKEN>"',
    'example_key = "1234567890abcdef1234567890abcdef"',
    'base64_asset = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"',
]
for i, ln in enumerate(HARD_NEG):
    repo = f"repo-{i % NREPOS:02d}"
    rdir = os.path.join(OUT, repo); os.makedirs(rdir, exist_ok=True)
    fp = os.path.join(rdir, f"neg_{i}.py")
    with open(fp, "w") as f:
        f.write("# fixture / placeholder — not a real secret\n" + ln + "\n")
    # not added to manifest as planted; any tool flagging these = false positive

json.dump(manifest, open(os.path.join(HERE, "manifest.json"), "w"), indent=1)
print(f"corpus: {len(secrets)} planted secrets across {NREPOS} repos, "
      f"{len(HARD_NEG)} hard-negative files")
print(f"types: {len(set(v for _,v in secrets))} distinct gitleaks rule-ids")
