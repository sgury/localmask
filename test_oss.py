#!/usr/bin/env python3
"""
LocalMask OSS integrity test
=============================
Run after any change to verify:
  - No Pro source files present
  - No bare imports of Pro modules
  - Edition defaults to free
  - All capability gates correct
  - Core scan / mask / rehydrate pipeline works
  - CLI and server_core import cleanly

Usage:
    python3 test_oss.py
    python3 test_oss.py --verbose

Exit code 0 = all good. Non-zero = failures (listed at the end).
"""

import argparse
import importlib.util
import logging
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--verbose", "-v", action="store_true")
args = parser.parse_args()

# ── Setup ─────────────────────────────────────────────────────────────────────

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:1")   # disable LLM calls
os.environ.pop("LOCALMASK_EDITION", None)                     # must default to free

if not args.verbose:
    logging.disable(logging.CRITICAL)

PASSES = []
FAILURES = []

def check(label, fn):
    try:
        fn()
        PASSES.append(label)
        if args.verbose:
            print(f"  ok  {label}")
    except Exception as e:
        FAILURES.append((label, str(e)))
        print(f"  FAIL  {label}")
        print(f"        {e}")


# ── Pro files that must never be present ──────────────────────────────────────

PRO_FILES = [
    "localmask/proxy.py",
    "localmask/askai.py",
    "sensitivity_classifier.py",
    "comment_scanner.py",
    "server.py",
    "ui.html",
    "localmask/audit.py",
    "localmask/ldap_auth.py",
]

def t_no_pro_files():
    import pathlib
    found = [f for f in PRO_FILES if pathlib.Path(f).exists()]
    assert not found, f"Pro-only files present in OSS repo: {found}"
check("no Pro source files on disk", t_no_pro_files)


# ── No bare 'from server import' (the Pro FastAPI server) ─────────────────────

def t_no_bare_server_import():
    import pathlib
    bad = []
    for py in pathlib.Path(".").rglob("*.py"):
        if any(p in str(py) for p in ["__pycache__", "venv", ".venv", "dist", "build",
                                       "test_oss.py"]):
            continue
        src = py.read_text(errors="ignore")
        if "from server import" in src or "\nimport server\n" in src:
            bad.append(str(py))
    assert not bad, f"Bare 'from server import' found in: {bad}"
check("no bare 'from server import' in any .py file", t_no_bare_server_import)


# ── .gitignore blocks all Pro files ───────────────────────────────────────────

def t_gitignore():
    gi = open(".gitignore").read()
    for f in ["localmask/proxy.py", "localmask/askai.py",
              "sensitivity_classifier.py", "server.py", "ui.html"]:
        assert f in gi, f"{f} not in .gitignore"
check(".gitignore blocks all Pro files", t_gitignore)


# ── Edition defaults to free ───────────────────────────────────────────────────

def t_edition_default():
    from localmask._edition import EDITION
    assert EDITION == "free", (
        f"EDITION defaults to '{EDITION}' — must be 'free' in OSS. "
        f"Check localmask/_edition.py line with os.environ.get('LOCALMASK_EDITION', ...)"
    )
check("EDITION defaults to 'free'", t_edition_default)


# ── Capability gates ───────────────────────────────────────────────────────────

FREE_CAPS  = ["regex_engine", "ner", "masking", "publish_masked",
              "git_sync", "mcp", "review_edit", "finance_token"]
PRO_CAPS   = ["llm_classifier", "learning", "web_ui", "ask_ai",
              "ai_proxy", "finance_modes"]
TEAM_CAPS  = ["org_rules", "shared_vault", "ldap_auth", "audit_log",
              "sso_saml", "closed_env"]

def t_free_caps_on():
    from localmask._edition import has_capability
    off = [c for c in FREE_CAPS if not has_capability(c)]
    assert not off, f"Free capabilities unexpectedly OFF: {off}"
check("all free-tier capabilities ON", t_free_caps_on)

def t_pro_caps_off():
    from localmask._edition import has_capability
    on = [c for c in PRO_CAPS + TEAM_CAPS if has_capability(c)]
    assert not on, f"Pro/Team capabilities unexpectedly ON (no license): {on}"
check("all Pro/Team capabilities OFF (no license)", t_pro_caps_off)

def t_pro_gate_raises():
    from localmask._edition import require
    for cap in ["ai_proxy", "llm_classifier", "web_ui", "ask_ai"]:
        try:
            require(cap)
            raise AssertionError(f"require('{cap}') should have raised PermissionError")
        except PermissionError:
            pass   # correct
check("require() raises PermissionError for Pro caps (not ImportError)", t_pro_gate_raises)

def t_localmask_proxy_absent():
    spec = importlib.util.find_spec("localmask.proxy")
    assert spec is None, f"localmask.proxy is still importable from: {spec}"
check("localmask.proxy not importable", t_localmask_proxy_absent)


# ── Core imports ───────────────────────────────────────────────────────────────

def t_regex_rules_import():
    from regex_rules_safe import RegexRulesSafe  # noqa
check("regex_rules_safe imports", t_regex_rules_import)

def t_engine_import():
    from localmask import engine  # noqa
check("localmask.engine imports", t_engine_import)

def t_cli_import():
    import cli  # noqa
check("cli imports", t_cli_import)

def t_server_core_import():
    import server_core
    assert server_core._ASKAI_AVAILABLE is False, (
        "_ASKAI_AVAILABLE should be False when localmask.askai is absent"
    )
check("server_core imports; _ASKAI_AVAILABLE=False", t_server_core_import)

def t_licensing_import():
    from licensing import LicenseManager
    lm = LicenseManager()
    assert lm.tier == "free", f"No-key tier should be 'free', got '{lm.tier}'"
check("licensing: no key → free tier", t_licensing_import)


# ── Scan → mask → rehydrate pipeline ─────────────────────────────────────────

SAMPLE_CONTENT = (
    "API_KEY=sk_live_abc123def456789\n"
    "DB_PASS=hunter2\n"
    "normal_line=hello world\n"
)

def t_scan():
    from regex_rules_safe import RegexRulesSafe
    dets = RegexRulesSafe.scan_file("test.env", SAMPLE_CONTENT, "standard")
    assert len(dets) >= 1, f"Expected ≥1 detections, got {len(dets)}"
check("regex scan finds credentials", t_scan)

def t_mask():
    from localmask.engine import _scan_file
    from localmask.state import _new_session
    session = _new_session("/tmp/oss_test", True)
    result = _scan_file(session, SAMPLE_CONTENT, "test.env")
    masked = result.get("masked", "")
    assert "~[" in masked, f"No mask tokens in output: {masked!r}"
    findings = result.get("findings", [])
    assert len(findings) >= 1, f"Expected ≥1 findings, got {findings}"
check("engine scan produces masked output with tokens", t_mask)

def t_rehydrate():
    from localmask.engine import _scan_file
    from localmask.masking import _rehydrate
    from localmask.state import _new_session
    session = _new_session("/tmp/oss_test2", True)
    result = _scan_file(session, "KEY=sk_live_abcdef123456789", "x.env")
    masked = result["masked"]
    assert "~[" in masked
    original = _rehydrate(session, masked)
    assert "sk_live_abcdef123456789" in original, (
        f"Rehydrate failed: {original!r} does not contain original value"
    )
check("mask → rehydrate round-trip", t_rehydrate)


# ── Upgrade notices (not crashes) for Pro features ────────────────────────────

def t_upgrade_notice():
    from localmask._edition import upgrade_notice
    for cap in ["llm_classifier", "ai_proxy", "ask_ai"]:
        notice = upgrade_notice(cap)
        assert "PRO" in notice.upper() or "localmaskpro" in notice.lower(), (
            f"upgrade_notice('{cap}') missing upgrade text: {notice!r}"
        )
check("upgrade_notice() returns helpful text for all Pro caps", t_upgrade_notice)


# ── Results ───────────────────────────────────────────────────────────────────

total = len(PASSES) + len(FAILURES)
print()
print("=" * 60)
print(f"LocalMask OSS integrity: {len(PASSES)}/{total} passed")
print("=" * 60)

if not args.verbose and PASSES:
    for p in PASSES:
        print(f"  ok  {p}")

if FAILURES:
    print()
    print(f"FAILED ({len(FAILURES)}):")
    for label, err in FAILURES:
        print(f"  ✗  {label}")
        print(f"     {err}")
    sys.exit(1)
else:
    print()
    print("All checks passed — OSS is clean and fully functional.")
    sys.exit(0)
