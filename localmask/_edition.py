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

# Overwritten at build time by build-dist.sh. Env var wins for dev/testing.
EDITION = os.environ.get("LOCALMASK_EDITION", "free")

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
    "org_rules":      "ent",    # shared team rules server
}

_ORDER = {"free": 0, "pro": 1, "ent": 2}


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
    """Effective edition = max(build-time floor, activated license tier)."""
    lic = _license_tier()
    return EDITION if _ORDER.get(EDITION, 0) >= _ORDER.get(lic, 0) else lic


def has_capability(cap: str) -> bool:
    """True if the current effective edition includes `cap` AND the source
    for it is actually present (a free build physically lacks Pro files)."""
    need = _CAP_MIN_EDITION.get(cap, "pro")
    if _ORDER.get(edition(), 0) < _ORDER.get(need, 1):
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
            f"'{cap}' is a {need.upper()} feature — this is the "
            f"{EDITION.upper()} edition. Upgrade at https://localmaskpro.com "
            f"(activate a license key with `localmask activate <key>`)."
        )


def upgrade_notice(cap: str) -> str:
    need = _CAP_MIN_EDITION.get(cap, "pro")
    return (f"⚡ {cap} requires the {need.upper()} edition. "
            f"You're on {EDITION.upper()} (regex engine, 100% local). "
            f"Upgrade: https://localmaskpro.com")
