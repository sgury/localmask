"""Edition marker and capability map.

Everything runs 100% locally in both editions — no phone-home, no cloud
dependency for detection or masking. The only capability that ever leaves
the machine is `ask_ai` (and only masked tokens), and it is Pro-only and
opt-in.

The build script overwrites EDITION when packaging:
  free → this file says "free"; the Pro-only source files are not shipped.
  pro  → this file says "pro"; all files shipped.

At runtime a file may be physically absent (free build) OR present but
license-gated (single-tree dev). `capabilities()` reconciles both.
"""
import os

# Overwritten at build time by build-dist.sh. In the dev tree the env var
# wins for testing; DIST BUILDS GET A LITERAL "free" WITH NO ENV OVERRIDE —
# paid capabilities unlock only through an activated (signed) license.
EDITION = os.environ.get("LOCALMASK_EDITION", "pro")

# Baked at build time. RELEASE_DATE (YYYYMMDD) anchors the perpetual-license
# update window: an LM2 license covers this build iff RELEASE_DATE falls
# inside the license's updates_until. Empty in the dev tree.
VERSION = "dev"
RELEASE_DATE = ""

# Capability → minimum edition that includes it.
_CAP_MIN_EDITION = {
    "regex_engine":   "free",   # 27+ credential patterns
    "ner":            "free",   # regex-fallback NER (no heavy deps)
    "masking":        "free",   # tokenise + rehydrate
    "publish_masked": "free",   # push masked copy to a git remote
    "git_sync":       "free",   # re-scan on change, stable tokens
    "mcp":            "free",   # MCP server
    "llm_classifier": "pro",    # local Ollama sensitivity model
    "learning":       "pro",    # feedback + embedding generalisation
    "web_ui":         "pro",    # dashboard
    "ask_ai":         "pro",    # cloud Q&A over masked repo (only egress)
    "ai_proxy":       "pro",    # prompt-firewall proxy (BYO AI, masked egress)
    "review_edit":    "free",   # manually edit detections: mask / allow / teach
    "finance_relative": "free", # Finance Mode: relative ratios (the OSS hook)
    "finance_modes":  "pro",    # Finance Mode: token/bucket opacity choice
    "org_rules":      "team",   # shared team rules server
    "shared_vault":   "team",   # team-wide Redis token vault (consistent tokens)
    # Team and Enterprise share the SAME feature set — the ONLY difference is
    # seat count (Enterprise = unlimited; see seat enforcement in
    # org-server/org_api.py /api/validate). So LDAP/audit/SSO are team-tier too.
    "ldap_auth":      "team",   # LDAP/AD auth + group→tier mapping
    "audit_log":      "team",   # tamper-evident audit trail + export (SIEM)
    "sso_saml":       "team",   # SSO sign-in on the org server (OIDC + SAML)
}

_ORDER = {"free": 0, "pro": 1, "team": 2, "ent": 3}


def _license_tier() -> str:
    """Locally-activated license tier, if any (offline checksum, no network).

    A valid key can only *raise* capability within a full tree — it can never
    conjure source files the build didn't ship, so the free package stays free.
    """
    try:
        from licensing import LicenseManager
        return LicenseManager().tier
    except Exception:
        return "free"


def edition() -> str:
    """Effective edition = max(build-time floor, activated license tier).

    This is a DISPLAY value only. Paid capability authorization does NOT use
    it — see `has_capability`/`_authorized_tier`."""
    lic = _license_tier()
    return EDITION if _ORDER.get(EDITION, 0) >= _ORDER.get(lic, 0) else lic


def _authorized_tier(need: str) -> str:
    """Tier that authorizes a capability requiring `need`.

    Free capabilities ride the baked edition floor (no license required).
    PAID capabilities (pro/team/ent) authorize ONLY on a valid, signed
    license tier (`_license_tier()` — Ed25519, unforgeable). The baked
    EDITION flag can *lower* capability but can never *raise* it, so editing
    `EDITION = "free"` -> `"pro"` in the shipped source unlocks nothing.
    Bypassing this now requires tampering with the signature check itself,
    not flipping a flag."""
    if _ORDER.get(need, 1) <= _ORDER["free"]:
        return edition()
    return _license_tier()


def has_capability(cap: str) -> bool:
    """True if a capability is authorized for the current tier AND its source
    is actually present (a free build physically lacks Pro files)."""
    need = _CAP_MIN_EDITION.get(cap, "pro")
    if _ORDER.get(_authorized_tier(need), 0) < _ORDER.get(need, 1):
        return False
    # Guard against a license claiming a tier whose files weren't shipped.
    return _source_present(cap)


def _source_present(cap: str) -> bool:
    import importlib.util as _u
    needed_module = {
        "llm_classifier": "sensitivity_classifier",
        "learning": "sensitivity_classifier",
        "ask_ai": "localmask.askai",
        "ai_proxy": "localmask.proxy",
        "ldap_auth": "localmask.ldap_auth",
        "audit_log": "localmask.audit",
    }.get(cap)
    if not needed_module:
        return True
    return _u.find_spec(needed_module) is not None


def capabilities() -> dict:
    """Map of capability → bool for the current edition."""
    return {cap: has_capability(cap) for cap in _CAP_MIN_EDITION}


def require(cap: str) -> None:
    """Raise a clear upgrade message if `cap` is not in this edition."""
    if not has_capability(cap):
        need = _CAP_MIN_EDITION.get(cap, "pro")
        raise PermissionError(
            f"'{cap}' is a {need.upper()} feature — you're running as "
            f"{edition().upper()}. Upgrade at https://localmaskpro.com "
            f"(activate a license key with `localmask activate <key>`)."
        )


def upgrade_notice(cap: str) -> str:
    need = _CAP_MIN_EDITION.get(cap, "pro")
    return (f"⚡ {cap} requires the {need.upper()} edition. "
            f"You're running as {edition().upper()} (regex engine, 100% local). "
            f"Upgrade: https://localmaskpro.com")
