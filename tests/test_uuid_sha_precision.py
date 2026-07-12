"""UUID / git-SHA precision (2026-07-12): a context-LESS UUID or 40-hex
(SHA-1 / git object id) is an identifier or digest, not a secret — it must NOT
be flagged. But the same shape IS still caught when a secret keyword labels it
(password=, a Consul ACL token key, …). Passwords must never regress."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LOCALMASK_EDITION", "free")
os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:1")

import localmask.engine as _E  # noqa: E402
_E._get_bert = lambda: None
from localmask.engine import _scan_file  # noqa: E402
from localmask.state import _new_session  # noqa: E402


def _subs(code, fname="x.py"):
    s = _new_session(".", False)
    s["sensitivity"] = "standard"
    return [d.get("subtype") for d in _scan_file(s, code, fname).get("findings", [])]


# Context-less UUIDs and git/SHA-1 hashes must be clean (no secret flagged).
CLEAN = [
    'id = "550e8400-e29b-41d4-a716-446655440000"',
    'ID = "550E8400-E29B-41D4-A716-446655440000"',
    "GET /v1/users/f47ac10b-58cc-4372-a567-0e02b2c3d479",
    'SHA = "a1b2c3d4e5f6789012345678901234567890abcd"',
    'COMMIT_SHA = "a1b2c3d4e5f6789012345678901234567890abcd"',
    "commit a1b2c3d4e5f6789012345678901234567890abcd",
    "AZURE_TENANT_ID=72f988bf-86f1-41af-91ab-2d7cd011db47",
]

# Passwords — must ALWAYS be caught, including UUID/SHA-shaped values that carry
# a password keyword (the context path wins over the identifier suppression).
PASSWORDS = [
    'password = "Sup3rS3cret!2024"',
    'DB_PASSWORD = "Pg$ecure#Pr0d_2024"',
    'password: "M4il!Srv9"',
    'login_password = "Adm1n!Pass99"',
    "PGPASSWORD=Str0ng!Db2024",
    'password = "550e8400-e29b-41d4-a716-446655440000"',
    'password = "a1b2c3d4e5f6789012345678901234567890abcd"',
]

# Real hex/UUID secrets that DO carry a key/token context stay caught.
KEPT = [
    'ENCRYPTION_KEY = "5f4dcc3b5aa765d61d8327deb882cf99"',      # 32-hex tradeoff
    'API_KEY = "a1b2c3d4e5f6789012345678901234567890abcd"',     # keyworded 40-hex
]


def test_contextless_uuid_and_sha_not_flagged():
    for code in CLEAN:
        assert _subs(code) == [], f"expected clean, got {_subs(code)}: {code}"


def test_passwords_always_caught():
    for code in PASSWORDS:
        subs = _subs(code)
        assert subs, f"password MISSED: {code}"
        assert any("password" in (t or "") or t in ("secret",) for t in subs), \
            f"password mis-typed {subs}: {code}"


def test_keyworded_hex_secrets_still_caught():
    for code in KEPT:
        assert _subs(code), f"keyworded secret MISSED: {code}"


def test_consul_acl_agent_token_uuid_caught():
    # A Consul ACL agent token is a UUID and a real secret — still caught in HCL.
    hcl = 'tokens {\n  agent = "f7a8b9c0-d1e2-3f4a-5b6c-7d8e9f0a1b2c"\n}\n'
    assert _subs(hcl, "config.hcl"), "Consul agent UUID token must be caught"
    # ...but a non-UUID agent pool name is not a secret.
    assert _subs('agent = "consul-server-pool-1"', "config.hcl") == []
