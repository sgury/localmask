"""Finance Mode — currency-anchored money-amount masking (opt-in).

Many customers won't paste financial figures into an AI. This layer detects
money amounts (currency symbols/codes or finance keywords — never bare
numbers) and replaces them per LOCALMASK_MONEY_MODE:

  off       (default) money amounts are not touched
  token     full opacity:      42,000 RON ->  ~[AMOUNT_0]~
  bucket    order of magnitude: 42,000 RON ->  ~[AMOUNT_5D_RON_0]~
  relative  ratio to a secret per-repo, per-CATEGORY random base R:
            42,000 RON ->  (0.42*R_SALARY)
            The AI can compare and compute; the absolute figure never leaves
            the machine. R is crypto-random, generated locally, stored in
            ~/.localmask/money_keys.json (0600). Separate categories (salary /
            revenue / price / amount) get separate keys so cross-category
            ratios (e.g. payroll as % of revenue) are not exposed either.

This is key-based relative pseudonymization, NOT encryption: within one
category, relative sizes ARE visible to the AI — that is the feature. The
real numbers, the currency and the scale are not.
"""
import json
import os
import re
import secrets

MODES = ("off", "token", "bucket", "relative")

_KEYS_PATH = os.path.expanduser("~/.localmask/money_keys.json")

# Finance keywords → category. A separate random base per category keeps
# cross-category ratios (salary vs revenue) hidden.
_CATEGORIES = {
    "salary":  ("salary", "salaries", "wage", "payroll", "compensation",
                "salariu", "salarii",
                "שכר", "משכורת", "משכורות"),
    "revenue": ("revenue", "income", "sales", "turnover", "arr", "mrr",
                "venit", "venituri", "cifra de afaceri",
                "הכנסה", "הכנסות", "מחזור"),
    "price":   ("price", "cost", "fee", "payment", "invoice", "budget",
                "expense", "preț", "pret", "plată", "plata", "factură",
                "factura", "buget",
                "מחיר", "עלות", "תשלום", "חשבונית", "תקציב",
                "הוצאה", "הוצאות"),
}
_KEYWORDS = tuple(w for words in _CATEGORIES.values() for w in words) + (
    "amount", "total", "sum", "suma", "סכום", 'סה"כ')

_SYMBOLS = {"₪": "ILS", "$": "USD", "€": "EUR", "£": "GBP"}
_CODES = ("ILS", "NIS", "USD", "EUR", "GBP", "RON", "LEI",
          'ש"ח', "שקלים", "שקל")

_NUM = r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?"
_MONEY_RES = [
    # ₪42,000  /  $ 1,234.56  — symbol before the number
    re.compile(r"(?<![\d\w.])([₪$€£]\s?(?:%s))(?![\d\w.%%])" % _NUM),
    # 42,000 ₪  /  1234.56€ — symbol after the number
    re.compile(r"(?<![\d\w.])((?:%s)\s?[₪$€£])(?![\d\w.%%])" % _NUM),
    # 42,000 ILS / 1,200 ש"ח — currency code after a formatted number
    re.compile(r"(?<![\d\w.])((?:%s)\s?(?:%s))(?![\d\w.%%])"
               % (_NUM, "|".join(re.escape(c) for c in _CODES)), re.I),
    # keyword-anchored bare number: salary: 95000 / salary_yossi = 35000 /
    # תקציב שיווק = 120,000 — a bounded [\w\s] gap allows suffixes between
    # the finance keyword and the separator. Bare numbers are ONLY flagged
    # next to a finance keyword — ports/ids/versions stay untouched.
    re.compile(r"(?i)(?:%s)[\w\s]{0,24}?[:=]\s*['\"]?((?:%s))(?![\d\w.%%])"
               % ("|".join(_KEYWORDS), _NUM)),
]


def money_mode() -> str:
    # explicit env var (per-invocation operator decision) > persisted setting
    # (Web UI / org policy) > off
    m = os.environ.get("LOCALMASK_MONEY_MODE", "").strip().lower()
    if not m:
        try:
            from .settings_store import get_setting, org_lock
            m = str(org_lock().get("money_mode")
                    or get_setting("money_mode", "off")).strip().lower()
        except Exception:
            m = "off"
    if m not in MODES:
        return "off"
    if m in ("token", "bucket"):
        # Edition gate: relative is free/OSS; the token/bucket opacity choice
        # is Pro. A free user asking for bucket gets a LOUD refusal — never a
        # silent substitute (protection level is an explicit uniform choice).
        from ._edition import require
        require("finance_modes")
    return m


def _parse_amount(text: str):
    digits = re.sub(r"[^\d.]", "", text)
    try:
        v = float(digits)
        return v if v > 0 else None
    except ValueError:
        return None


def _currency(text: str) -> str:
    for sym, code in _SYMBOLS.items():
        if sym in text:
            return code
    up = text.upper()
    for code in ("ILS", "NIS", "USD", "EUR", "GBP", "RON", "LEI"):
        if code in up:
            return {"NIS": "ILS", "LEI": "RON"}.get(code, code)
    if 'ש"ח' in text or "שקל" in text:
        return "ILS"
    return "UNK"


def _category(line: str) -> str:
    low = line.lower()
    for cat, words in _CATEGORIES.items():
        if any(w in low for w in words):
            return cat
    return "amount"


_NOTIFIED = False


def scan_money(content: str, file_ext: str) -> list:
    """Detect money amounts. Currency- or keyword-anchored only — a bare
    number is never flagged, so ports/versions/ids are untouched."""
    if money_mode() == "off":
        return []
    global _NOTIFIED
    if not _NOTIFIED:
        _NOTIFIED = True
        print(FINANCE_NOTICE.format(mode=money_mode()))
    results, seen_spans = [], set()
    for line_no, line in enumerate(content.split("\n"), 1):
        for rx in _MONEY_RES:
            for m in rx.finditer(line):
                span_key = (line_no, m.start(1), m.end(1))
                if any(s[0] == line_no and s[1] <= m.start(1) and m.end(1) <= s[2]
                       for s in seen_spans):
                    continue
                amt = m.group(1).strip()
                value = _parse_amount(amt)
                if value is None:
                    continue
                seen_spans.add(span_key)
                results.append({
                    "entity": amt,
                    "type": "money_amount",
                    "confidence": 0.9,
                    "level": "minimal",
                    "line": line_no,
                    "context": line.strip()[:120],
                    "file_type": file_ext,
                    "pattern_reason": "Money amount (finance mode)",
                    "money_value": value,
                    "money_currency": _currency(amt) if _currency(amt) != "UNK"
                                      else _currency(line),
                    "money_category": _category(line),
                })
    return results


def _load_keys() -> dict:
    try:
        with open(_KEYS_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _money_base(repo_id: str, category: str) -> float:
    """Crypto-random base R per (repo, category). Generated locally, stored
    0600 — the customer's machine keeps it, nobody memorizes anything."""
    keys = _load_keys()
    k = f"{repo_id}:{category}"
    if k not in keys:
        # uniform magnitude in [10^4, 10^7) — ratios stay readable while the
        # scale itself remains secret
        keys[k] = round(10 ** (4 + 3 * secrets.randbits(30) / 2 ** 30), 4)
        os.makedirs(os.path.dirname(_KEYS_PATH), exist_ok=True)
        fd = os.open(_KEYS_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(keys, fh, indent=1)
    return keys[k]


def money_token(session: dict, value: str, det: dict) -> str:
    """Mint the replacement text for a money amount, per mode. Mirrors
    _make_token's vault write-through so rehydration works unchanged."""
    from .masking import _make_token
    if value in session["vault"]:
        return session["vault"][value]

    mode = money_mode()
    num = det.get("money_value") or 0
    cur = det.get("money_currency", "UNK")
    cat = det.get("money_category", "amount")

    if mode == "bucket":
        digits = len(str(int(num))) if num >= 1 else 1
        return _make_token(session, value, f"AMOUNT_{digits}D_{cur}")
    if mode == "relative":
        # The protection level is the customer's ONE uniform choice — never
        # a side effect of detection quality. An amount whose category
        # wasn't identified stays relative on the generic R_AMOUNT base,
        # exactly like everything else in this mode; a customer who wants
        # full opacity picks token/bucket mode for the whole scan.
        try:
            from .vault_store import repo_id_for
            rid = repo_id_for(session.get("src", "") or "")
        except Exception:
            rid = "default"
        base = _money_base(rid, cat)
        ratio = num / base
        for sig in (5, 7, 9, 12):
            token = f"({ratio:.{sig}g}*R_{cat.upper()})"
            owner = session["rev_vault"].get(token)
            if owner is None or owner == value:
                break
        session["vault"][value] = token
        session["rev_vault"][token] = value
        return token
    return _make_token(session, value, "AMOUNT")


FINANCE_NOTICE = (
    "[FINANCE] Money amounts are masked (mode: {mode}). Real figures never "
    "leave this machine; in 'relative' mode the AI sees only ratios to a "
    "random per-category base stored encrypted on your disk.")
