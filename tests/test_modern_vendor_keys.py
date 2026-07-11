"""Modern-vendor key patterns (2026-07-11): OpenAI project/service keys, Okta,
Groq, Perplexity, Sentry auth, widened Doppler. Each canonical token must be
detected AS ITS OWN type (no overlap / misclassification), and existing vendor
tokens must keep their own type."""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LOCALMASK_EDITION", "free")
os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:1")

import localmask.engine as _E  # noqa: E402
_E._get_bert = lambda: None
from localmask.engine import _scan_file  # noqa: E402
from localmask.state import _new_session  # noqa: E402


def _filler(name, ln):
    return (hashlib.sha256(name.encode()).hexdigest() * 4)[:ln]


def _types(tok):
    s = _new_session(".", False)
    s["sensitivity"] = "standard"
    r = _scan_file(s, f'X = "{tok}"', "x.py")
    return sorted({d.get("subtype") for d in r.get("findings", [])})


NEW = {
    "openai_project_key": "sk-proj-" + _filler("openai", 60),
    "openai_project_key_svcacct": "sk-svcacct-" + _filler("svc", 55),
    "okta_api_token": "SSWS 00" + _filler("okta", 40),
    "groq_api_key": "gsk_" + _filler("groq", 52),
    "perplexity_api_key": "pplx-" + _filler("pplx", 48),
    "sentry_auth_token": "sntrys_" + _filler("sentry", 64),
    "doppler_token": "dp.st." + _filler("dop", 42),
}

# Expected type differs from the case name only for the two OpenAI variants.
EXPECT = {k: ("openai_project_key" if k.startswith("openai_project_key") else k)
          for k in NEW}


def test_new_vendor_tokens_type_as_themselves():
    for name, tok in NEW.items():
        assert _types(tok) == [EXPECT[name]], f"{name}: {_types(tok)}"


def test_existing_vendors_not_stolen_by_new_rules():
    # sk-ant- must stay anthropic; legacy sk-[48] must stay openai_key.
    assert _types("sk-ant-api03-" + _filler("ant", 80)) == ["anthropic_key"]
    assert _types("sk-" + _filler("legacy", 48)) == ["openai_key"]


def _hexf(name, ln):
    """Deterministic lowercase-hex filler for hex-format vendor tokens."""
    h = hashlib.sha256(name.encode()).hexdigest()
    return (h * 3)[:ln]


def _scan_code(code):
    s = _new_session(".", False)
    s["sensitivity"] = "standard"
    r = _scan_file(s, code, "x.py")
    return sorted({d.get("subtype") for d in r.get("findings", [])})


# Keyword-anchored vendors: the rule fires only when the vendor keyword is near
# the token, and it extracts the capture group (token only) — verify both.
KW = {
    "vercel_token": f'VERCEL_TOKEN = "{_filler("vercel", 24)}"',
    "fastly_api_token": f'FASTLY_API_TOKEN = "{_filler("fastly", 32)}"',
    "linode_token": f'LINODE_TOKEN = "{_hexf("linode", 64)}"',
    "kraken_api_key": f'KRAKEN_API_KEY = "{_filler("kraken", 54)}=="',
    "etsy_keystring": f'ETSY_KEYSTRING = "{_hexf("etsy", 24)}"',
}


def test_keyword_anchored_vendors_type_as_themselves():
    for expected, code in KW.items():
        assert _scan_code(code) == [expected], f"{expected}: {_scan_code(code)}"
