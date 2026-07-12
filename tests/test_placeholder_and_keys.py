"""Blindspot-pass fixes (2026-07-12):
  1. Placeholder values assigned to secret/api_key/token/password variables
     (YOUR_API_KEY_HERE, xxxx…, your-secret-key, replace-with-…) must NOT be
     flagged — they're the #1 source of secret-scanner noise.
  2. PGP private key blocks (`-----BEGIN PGP PRIVATE KEY BLOCK-----`) must be
     caught like every other private key.
Real secrets and real passwords must never regress."""
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


PLACEHOLDERS = [
    'api_key = "YOUR_API_KEY_HERE"',
    'token = "xxxxxxxxxxxxxxxx"',
    'SECRET = "your-secret-key"',
    'password = "replace-with-real-password"',
    'api_key = "insert-your-key-here"',
    'password = "changeme"',
]

REAL_SECRETS = [
    'password = "Sup3rS3cret!2024"',
    'api_key = "a1b2C3d4E5f6G7h8I9j0K1"',
    'DB_PASSWORD = "Pg$ecure#Pr0d_2024"',
    'token = "ghp_1234567890abcdefABCDEFghijklmnop99"',
    # a real password that merely contains the word "replace" but not the
    # placeholder phrasing must survive.
    'password = "Replace2024!SecureX"',
]

PRIVATE_KEYS = [
    "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQdG\n-----END PGP PRIVATE KEY BLOCK-----",
]


def test_placeholders_not_flagged():
    for code in PLACEHOLDERS:
        assert _subs(code) == [], f"placeholder flagged: {code} -> {_subs(code)}"


def test_real_secrets_still_flagged():
    for code in REAL_SECRETS:
        assert _subs(code), f"real secret MISSED: {code}"


def test_all_private_key_types_caught():
    for pem in PRIVATE_KEYS:
        assert "private_key_header" in _subs(pem), f"private key MISSED: {pem[:40]}"
