"""IBAN detection (2026-07-12): promoted to standard sensitivity, gated by an
ISO-3166 country code + the mod-97 checksum so it fires on real IBANs (spaced or
contiguous) without stealing secret-shaped strings like a Twilio SID (AC…)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LOCALMASK_EDITION", "free")
os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:1")

import localmask.engine as _E  # noqa: E402
_E._get_bert = lambda: None
from localmask.engine import _scan_file, _iban_ok  # noqa: E402
from localmask.state import _new_session  # noqa: E402


def _has_iban(code):
    s = _new_session(".", False)
    s["sensitivity"] = "standard"
    return "iban" in [d.get("subtype")
                      for d in _scan_file(s, code, "x.py").get("findings", [])]


# Country-agnostic: the mod-97 checksum is the sole gate, so IBANs from ANY
# ISO country (including non-European and future ones) must be caught.
VALID = [
    "IBAN: DE89 3704 0044 0532 0130 00",
    'iban = "DE89370400440532013000"',
    'account = "GB82 WEST 1234 5698 7654 32"',
    "FR1420041010050500013M02606",
    "NO9386011117947",                          # Norway (15 chars)
    "KW81CBKU0000000000001234560101",           # Kuwait
    "BR9700360305000010009795493P1",            # Brazil
    "SC18SSCB11010000000000001497USD",          # Seychelles
]

# A Twilio Account SID (AC + 32 hex) — assembled from fragments so no
# secret-shaped literal sits in source (GitHub push protection / our scanners).
_TWILIO_SID = "AC" + "1234567890abcdef" + "1234567890abcdef"

# Must NOT be flagged as IBAN:
NOT_IBAN = [
    'IBAN: DE89370400440532013001',                        # bad checksum
    f'TWILIO_ACCOUNT_SID = "{_TWILIO_SID}"',               # not a country
    'X = "US00ABCDEFGHIJKLMNOP1234"',                      # US has no IBAN
    'HASH = "AB12cd34ef56ab78cd90ef12"',                   # random hex-ish
]


def test_valid_ibans_detected_at_standard():
    for code in VALID:
        assert _has_iban(code), f"valid IBAN missed: {code}"


def test_non_ibans_not_flagged():
    for code in NOT_IBAN:
        assert not _has_iban(code), f"wrongly flagged as IBAN: {code}"


def test_checksum_validator():
    assert _iban_ok("DE89370400440532013000")
    assert _iban_ok("GB82 WEST 1234 5698 7654 32")
    assert not _iban_ok("DE89370400440532013001")
    assert not _iban_ok(_TWILIO_SID)
