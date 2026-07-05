"""Token minting and value->token replacement (mask / rehydrate)."""
import re


def _make_token(session: dict, value: str, subtype: str) -> str:
    """Return existing token or mint a new one.

    With a vault store attached, minting is atomic and race-safe (reserve the
    counter, then put-if-absent) so a shared/team store never collides across
    machines; without one, it's the plain in-memory counter."""
    if value in session["vault"]:
        return session["vault"][value]
    key = subtype.upper().replace(" ", "_").replace("-", "_")
    store = session.get("_store")

    if store is not None:
        # another machine/session may already have tokenised this value
        existing = store.token_for(value)
        if existing:
            session["vault"][value] = existing
            session["rev_vault"][existing] = value
            return existing
        n = store.reserve(key)                       # atomic across machines
        token = f"~[{key}_{n}]~"
        winner = store.put_if_absent(value, token, subtype)  # race-safe
        session["vault"][value] = winner
        session["rev_vault"][winner] = value
        session["tok_count"][key] = max(session["tok_count"].get(key, 0), n + 1)
        return winner

    n = session["tok_count"].get(key, 0)
    session["tok_count"][key] = n + 1
    token = f"~[{key}_{n}]~"
    session["vault"][value] = token
    session["rev_vault"][token] = value
    return token


# ── Key-position patterns: these are structural "names", never secrets ────────
# Each regex matches a span where the value is in a KEY/NAME position.
# During masking, these spans are protected — only VALUE positions get masked.
_KEY_POSITION_PATTERNS = [
    # XML/HTML: <tag key="..." /> or <tag name="..." />
    re.compile(r'(?i)\b(?:key|name)\s*=\s*["\'][^"\']*["\']'),
    # XML/HTML: attribute names: attrName="..."
    re.compile(r'(?i)\b[a-zA-Z_][\w]*\s*=\s*(?=["\'])'),
    # JSON keys: "keyName":  (left side of colon)
    re.compile(r'["\'][^"\']+["\']\s*:'),
    # INI/config/YAML: KeyName = ... or key_name: ... (left of = or :)
    re.compile(r'(?m)^\s*[a-zA-Z_@$][\w.]*\s*(?==|:)'),
    # SQL column references: alias.Column, schema.Table, dbo.ProcName
    re.compile(r'\b[a-zA-Z_]\w{0,30}\.[A-Za-z_]\w{2,}\b'),
    # SQL variable/param names: @VarName, $var_name
    re.compile(r'[@$][a-zA-Z_]\w+'),
    # DECLARE @Var TYPE — the variable name
    re.compile(r'(?i)\bDECLARE\s+@\w+'),
    # SQL SET @Var = ... — protect @Var
    re.compile(r'(?i)\bSET\s+@\w+'),
    # CONCAT( column refs  — protect bare identifiers before commas in CONCAT
    re.compile(r'(?i)\bCONCAT\s*\([^)]+\)'),
]


def _context_aware_replace(text: str, value: str, token: str) -> str:
    """Replace value→token but protect key/name positions.
    Keys stay visible, only values get masked."""
    if value not in text:
        return text

    protected = {}
    counter = [0]

    def _protect(m):
        full = m.group(0)
        if value in full:
            placeholder = f"\x00P{counter[0]}\x00"
            counter[0] += 1
            protected[placeholder] = full
            return placeholder
        return full

    for pat in _KEY_POSITION_PATTERNS:
        text = pat.sub(_protect, text)

    # Now replace — only unprotected (value) positions get masked
    text = text.replace(value, token)

    # Restore protected key positions
    for placeholder, original in protected.items():
        text = text.replace(placeholder, original)

    return text


def _mask_text(s: dict, text: str) -> str:
    """Replace known secret values with their mask tokens.
    Sorted longest-first so 'prdpg01.meridian-fs.local' is replaced
    before 'meridian-fs.local' can partially break it.
    Uses word-boundary awareness to avoid partial hostname replacement."""
    import re
    vault_sorted = sorted(s["vault"].items(), key=lambda x: -len(x[0]))
    for value, token in vault_sorted:
        # Use word-boundary-aware replacement to avoid partial matches
        # e.g. don't replace "meridian-fs.local" inside "PRDORA02.meridian-fs.local"
        # A preceding dot or alphanumeric means this is part of a larger token
        pattern = r'(?<![.\w])' + re.escape(value) + r'(?![.\w])'
        text = re.sub(pattern, token, text)
    # Second pass: case-insensitive
    for value, token in vault_sorted:
        if token in text:
            continue
        pattern = r'(?<![.\w])' + re.escape(value) + r'(?![.\w])'
        text = re.sub(pattern, token, text, flags=re.IGNORECASE)
    return text


def _rehydrate(s: dict, text: str) -> str:
    for token, value in s["rev_vault"].items():
        text = text.replace(token, value)
    return text


