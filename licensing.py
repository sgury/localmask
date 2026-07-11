"""
LocalMask Pro — License Management & Code Protection.

Offline-first licensing. No mandatory phone-home. Free tier works without
any key.

LM2 key format (current): LM2.{b64url(payload_json)}.{b64url(ed25519_sig)}
  The payload is signed with a private key that exists ONLY on the license
  server; the public key ships below. Validation is fully offline and stays
  safe even with complete source access (Kerckhoffs): without the private
  key no one can mint a valid license.
  Semantics are perpetual-with-update-window: the license is valid forever
  on every build whose RELEASE_DATE is within the buyer's updates_until.

Legacy format: LM-{TIER}-{random_hex(16)}-[{expYYYYMMDD}-]{checksum_hex(4)}
  HMAC with an embedded (public) secret — forgeable by design, so it is
  accepted only when LOCALMASK_ACCEPT_LEGACY_KEYS=1 (dev/test trees).

Storage: ~/.localmask/license.json, ~/.localmask/usage.json
"""
import base64
import hashlib
import hmac
import json
import os
import platform
import secrets
import time
import uuid
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ── Constants ────────────────────────────────────────────────────────────────

LICENSE_DIR = os.path.expanduser("~/.localmask")
LICENSE_FILE = os.path.join(LICENSE_DIR, "license.json")
USAGE_FILE = os.path.join(LICENSE_DIR, "usage.json")

# Legacy HMAC secret (embedded → public → forgeable). Kept only so dev trees
# can keep using old keys behind LOCALMASK_ACCEPT_LEGACY_KEYS=1.
_SIGNING_SECRET = b"localmask-pro-2026-offline-license-validation"

# LM2: Ed25519 public verification key (raw 32 bytes, base64). The matching
# private key never ships — it lives only on the license server.
# LOCALMASK_LICENSE_PUBKEY overrides for dev/test trees.
_LM2_PUBKEY_B64 = "ONCTL67acgV/VBPM2yXk+qx6EJRp2K9LSHN2O22cLXc="

# Tier definitions — monthly limits
# Free tier: 10 scans & 10 asks in the first month, then 3/month after
TIERS = {
    "free": {
        "name": "Free",
        "scans_per_month": 3,
        "asks_per_month": 3,
        "scans_first_month": 10,
        "asks_first_month": 10,
        "custom_rules": False,
        "max_concurrent": 1,
    },
    "pro": {
        "name": "Pro",
        "scans_per_month": -1,  # unlimited
        "asks_per_month": -1,
        "custom_rules": True,
        "max_concurrent": 5,
    },
    "team": {
        "name": "Team",
        "scans_per_month": -1,
        "asks_per_month": -1,
        "custom_rules": True,
        "max_concurrent": 20,
    },
    "ent": {
        "name": "Enterprise",
        "scans_per_month": -1,
        "asks_per_month": -1,
        "custom_rules": True,
        "max_concurrent": -1,
    },
}

# Action → tier field mapping
ACTION_LIMITS = {
    "scan": "scans_per_month",
    "ask": "asks_per_month",
}


# ── Key Generation (for admin/testing) ───────────────────────────────────────

GRACE_DAYS = 7  # tier stays active this long past expiry before dropping to free


def generate_license_key(tier: str = "pro", years: int = 1) -> str:
    """Generate a license key.

    years > 0  → annual key that embeds an expiry date (the org buys a yearly
                 license; no monthly re-activation). Format:
                 LM-{TIER}-{random32}-{expYYYYMMDD}-{checksum}
    years <= 0 → perpetual key (legacy 4-part form), used for internal/testing.
    """
    if tier not in TIERS:
        raise ValueError(f"Unknown tier: {tier}. Use: {list(TIERS.keys())}")
    random_part = secrets.token_hex(16)
    if years and years > 0:
        exp = (datetime.now(timezone.utc) + timedelta(days=365 * years)).strftime("%Y%m%d")
        checksum = _compute_checksum(tier, random_part, exp)
        return f"LM-{tier.upper()}-{random_part}-{exp}-{checksum}"
    checksum = _compute_checksum(tier, random_part)
    return f"LM-{tier.upper()}-{random_part}-{checksum}"


def _compute_checksum(tier: str, random_part: str, exp: str = "") -> str:
    """HMAC-SHA256 checksum (first 4 hex chars). Expiry is signed too, so it
    can't be tampered with offline."""
    payload = f"{tier.lower()}{random_part}{exp}".encode()
    mac = hmac.new(_SIGNING_SECRET, payload, hashlib.sha256).hexdigest()
    return mac[:4]


def _validate_key_format(key: str) -> tuple:
    """Validate license key format.
    Returns (valid, tier, error, expires_at) — expires_at is an ISO date
    string ('' = perpetual)."""
    parts = key.split("-")
    if len(parts) not in (4, 5) or parts[0] != "LM":
        return False, "", "Invalid key format", ""

    tier = parts[1].lower()
    random_part = parts[2]
    if tier not in TIERS:
        return False, "", f"Unknown tier: {tier}", ""
    if len(random_part) != 32:
        return False, "", "Invalid key length", ""

    if len(parts) == 5:  # annual key with embedded expiry
        exp, provided_checksum = parts[3], parts[4]
        expected = _compute_checksum(tier, random_part, exp)
        if not hmac.compare_digest(provided_checksum, expected):
            return False, "", "Invalid checksum", ""
        try:
            exp_iso = datetime.strptime(exp, "%Y%m%d").replace(
                tzinfo=timezone.utc).isoformat()
        except ValueError:
            return False, "", "Invalid expiry", ""
        return True, tier, "", exp_iso

    provided_checksum = parts[3]  # perpetual key
    expected = _compute_checksum(tier, random_part)
    if not hmac.compare_digest(provided_checksum, expected):
        return False, "", "Invalid checksum", ""
    return True, tier, "", ""


def _machine_id() -> str:
    """Generate a machine-specific identifier."""
    raw = f"{platform.node()}-{uuid.getnode()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── LM2 (Ed25519-signed) keys ────────────────────────────────────────────────

def _legacy_keys_ok() -> bool:
    return os.environ.get("LOCALMASK_ACCEPT_LEGACY_KEYS", "") == "1"


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _validate_lm2(key: str) -> tuple:
    """Verify an LM2.{payload}.{sig} key. Returns (valid, tier, error, payload).

    payload: {"t": tier, "i": issued YYYYMMDD, "u": updates_until YYYYMMDD,
              "s": seats, "n": nonce}
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return False, "", ("License validation needs the 'cryptography' package "
                           "— pip install cryptography"), {}
    parts = key.strip().split(".")
    if len(parts) != 3 or parts[0] != "LM2":
        return False, "", "Invalid key format", {}
    try:
        payload_raw = _b64u_decode(parts[1])
        sig = _b64u_decode(parts[2])
        pub = base64.b64decode(
            os.environ.get("LOCALMASK_LICENSE_PUBKEY", _LM2_PUBKEY_B64))
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload_raw)
        payload = json.loads(payload_raw)
    except InvalidSignature:
        return False, "", "Invalid license signature", {}
    except Exception:
        return False, "", "Malformed license key", {}
    tier = str(payload.get("t", "")).lower()
    upd = str(payload.get("u", ""))
    if tier not in TIERS or tier == "free":
        return False, "", f"Unknown tier: {tier}", {}
    if not (len(upd) == 8 and upd.isdigit()):
        return False, "", "Malformed update window", {}
    return True, tier, "", payload


def _release_date() -> str:
    """This build's release date (YYYYMMDD), baked by build-dist.sh.
    Empty in the dev tree → every license covers it."""
    rd = os.environ.get("LOCALMASK_RELEASE_DATE", "")
    if rd:
        return rd
    try:
        from localmask._edition import RELEASE_DATE
        return RELEASE_DATE or ""
    except Exception:
        return ""


def _build_covered(updates_until: str) -> bool:
    """A license covers this build iff the build was released within the
    buyer's update window. Wall-clock time is irrelevant: what you bought
    keeps working forever."""
    rd = _release_date()
    return (not rd) or rd <= updates_until


# ── License Manager ──────────────────────────────────────────────────────────

class LicenseManager:
    """Manages license activation, validation, and usage tracking."""

    def __init__(self):
        os.makedirs(LICENSE_DIR, exist_ok=True)
        self._license = self._load_license()
        self._usage = self._load_usage()

    @property
    def tier(self) -> str:
        """Current tier name, re-validated from the stored key on every load —
        a hand-edited license.json (tier: pro, no valid key) resolves to free.

        LM2 keys: perpetual on covered builds (RELEASE_DATE ≤ updates_until);
        a build released after the window resolves to free.
        Legacy LM- keys: dev/test only (LOCALMASK_ACCEPT_LEGACY_KEYS=1),
        wall-clock expiry + grace as before."""
        key = self._license.get("license_key", "")
        if not key:
            return "free"
        if key.startswith("LM2."):
            valid, tier, _err, payload = _validate_lm2(key)
            if not valid or not _build_covered(str(payload.get("u", ""))):
                return "free"
            return tier
        if not _legacy_keys_ok():
            return "free"
        valid, tier, _err, _exp = _validate_key_format(key)
        if not valid:
            return "free"
        if tier != "free" and self._is_expired():
            return "free"
        return tier

    def _is_expired(self) -> bool:
        exp = self._license.get("expires_at", "")
        if not exp:
            return False  # perpetual
        try:
            exp_dt = datetime.fromisoformat(exp)
        except ValueError:
            return False
        return datetime.now(timezone.utc) > (exp_dt + timedelta(days=GRACE_DAYS))

    def days_remaining(self):
        exp = self._license.get("expires_at", "")
        if not exp:
            return None  # perpetual
        try:
            exp_dt = datetime.fromisoformat(exp)
        except ValueError:
            return None
        return (exp_dt - datetime.now(timezone.utc)).days

    @property
    def tier_config(self) -> dict:
        """Current tier limits."""
        return TIERS.get(self.tier, TIERS["free"])

    @property
    def is_activated(self) -> bool:
        return bool(self._license.get("license_key"))

    # ── Activation ───────────────────────────────────────────────────────

    def activate(self, license_key: str) -> dict:
        """Activate a license key. Fully offline validation."""
        license_key = license_key.strip()
        if license_key.startswith("LM2."):
            return self._activate_lm2(license_key)

        # Legacy LM- keys: dev/test trees only.
        if not _legacy_keys_ok():
            return {"ok": False, "error": (
                "This key uses the old format and can no longer be activated. "
                "Contact hello@localmaskpro.com for a replacement key.")}
        valid, tier, error, expires_at = _validate_key_format(license_key)
        if not valid:
            return {"ok": False, "error": error}
        if expires_at and datetime.now(timezone.utc) > (
                datetime.fromisoformat(expires_at) + timedelta(days=GRACE_DAYS)):
            return {"ok": False, "error": "This license has expired — please renew."}

        now = datetime.now(timezone.utc).isoformat()
        self._license = {
            "license_key": license_key,
            "tier": tier,
            "activated_at": now,
            "last_validated": now,
            "expires_at": expires_at,
            "machine_id": _machine_id(),
        }
        self._save_license()
        return {
            "ok": True,
            "tier": tier,
            "tier_name": TIERS[tier]["name"],
            "activated_at": now,
            "expires_at": expires_at or "perpetual",
        }

    def _activate_lm2(self, license_key: str) -> dict:
        valid, tier, error, payload = _validate_lm2(license_key)
        if not valid:
            return {"ok": False, "error": error}
        upd = str(payload.get("u", ""))
        upd_pretty = f"{upd[:4]}-{upd[4:6]}-{upd[6:]}"
        if not _build_covered(upd):
            rd = _release_date()
            rd_pretty = f"{rd[:4]}-{rd[4:6]}-{rd[6:]}"
            return {"ok": False, "error": (
                f"This license includes updates until {upd_pretty}, but this "
                f"version was released {rd_pretty}. Your license keeps working "
                f"forever on versions released within your window — download "
                f"one from your purchase link, or renew at "
                f"https://localmaskpro.com for the latest.")}
        now = datetime.now(timezone.utc).isoformat()
        self._license = {
            "license_key": license_key,
            "kind": "lm2",
            "tier": tier,
            "activated_at": now,
            "last_validated": now,
            "updates_until": upd,
            "seats": int(payload.get("s", 1) or 1),
            "machine_id": _machine_id(),
        }
        self._save_license()
        return {
            "ok": True,
            "tier": tier,
            "tier_name": TIERS[tier]["name"],
            "activated_at": now,
            "updates_until": upd_pretty,
            "note": ("Perpetual license: every version released before "
                     f"{upd_pretty} is yours forever."),
        }

    def deactivate(self) -> dict:
        """Remove license, revert to free tier."""
        self._license = {}
        self._save_license()
        return {"ok": True, "tier": "free"}

    # ── Usage Tracking ───────────────────────────────────────────────────

    def _is_first_month(self) -> bool:
        """Check if the user is still in their first month (from first usage)."""
        first_use = self._usage.get("_first_use", "")
        if not first_use:
            return True  # no usage yet → will be first month
        try:
            first_dt = datetime.fromisoformat(first_use)
            now = datetime.now(timezone.utc)
            return (now - first_dt).days < 30
        except ValueError:
            return False

    def _get_monthly_limit(self, action: str) -> int:
        """Get the effective monthly limit for an action, considering first-month bonus."""
        tier_cfg = self.tier_config
        limit_field = ACTION_LIMITS.get(action)
        if not limit_field:
            return -1
        base_limit = tier_cfg.get(limit_field, -1)
        if base_limit == -1:
            return -1  # unlimited

        # Check first-month bonus (free tier only)
        if self.tier == "free" and self._is_first_month():
            first_month_field = f"{action}s_first_month"
            return tier_cfg.get(first_month_field, base_limit)

        return base_limit

    def check_or_raise(self, action: str):
        """Check if action is allowed under current tier. Raises RuntimeError if not."""
        limit_field = ACTION_LIMITS.get(action)
        if not limit_field:
            return  # unknown action → allow

        limit = self._get_monthly_limit(action)
        if limit == -1:
            return  # unlimited

        month_key = self._this_month()
        usage_month = self._usage.get(month_key, {})
        current = usage_month.get(action, 0)

        if current >= limit:
            tier_name = self.tier_config["name"]
            first_month = self._is_first_month()
            period = "first month" if first_month else "monthly"
            raise RuntimeError(
                f"Monthly {action} limit reached ({current}/{limit} for {tier_name} tier). "
                f"Upgrade to Pro for unlimited access — localmask activate LM-PRO-..."
            )

    def record_usage(self, action: str):
        """Increment monthly counter for an action."""
        month_key = self._this_month()
        if month_key not in self._usage:
            self._cleanup_usage()
            self._usage[month_key] = {}
        month_usage = self._usage[month_key]
        month_usage[action] = month_usage.get(action, 0) + 1

        # Record first-ever usage timestamp
        if "_first_use" not in self._usage:
            self._usage["_first_use"] = datetime.now(timezone.utc).isoformat()

        self._save_usage()

    def get_status(self) -> dict:
        """Return current license status and usage."""
        month_key = self._this_month()
        usage_month = self._usage.get(month_key, {})
        tier_cfg = self.tier_config
        first_month = self._is_first_month()

        limits = {}
        for action, field in ACTION_LIMITS.items():
            limit = self._get_monthly_limit(action)
            current = usage_month.get(action, 0)
            limits[action] = {
                "used": current,
                "limit": limit if limit != -1 else "unlimited",
                "remaining": (limit - current) if limit != -1 else "unlimited",
            }

        days_left = self.days_remaining()
        status = {
            "tier": self.tier,
            "tier_name": tier_cfg["name"],
            "is_activated": self.is_activated,
            "license_key": self._mask_key(),
            "activated_at": self._license.get("activated_at", ""),
            "expires_at": self._license.get("expires_at", "") or "perpetual",
            "days_remaining": days_left,
            "custom_rules": tier_cfg["custom_rules"],
            "usage_this_month": limits,
            "billing_period": "annual",
        }
        if self._license.get("kind") == "lm2":
            upd = self._license.get("updates_until", "")
            upd_pretty = f"{upd[:4]}-{upd[4:6]}-{upd[6:]}" if len(upd) == 8 else upd
            status["billing_period"] = "one-time"
            status["license_model"] = (
                f"Perpetual — versions released before {upd_pretty} are "
                f"yours forever; updates included until {upd_pretty}.")
            status["updates_until"] = upd_pretty
            if not _build_covered(upd):
                status["renewal_notice"] = (
                    f"This version was released after your update window "
                    f"({upd_pretty}) — running as Free. Use a version from "
                    f"your purchase link, or renew at https://localmaskpro.com.")
        elif days_left is not None and days_left <= 30:
            status["renewal_notice"] = (
                f"Your license expires in {days_left} days — renew at "
                f"https://localmaskpro.com to keep Pro features.")
        if self.tier == "free":
            status["first_month_bonus"] = first_month
            if first_month:
                status["note"] = "First month: 10 scans & 10 asks free. After that: 3/month."
        return status

    # ── Feature Gates ────────────────────────────────────────────────────

    def can_use_custom_rules(self) -> bool:
        return self.tier_config.get("custom_rules", False)

    # ── Persistence ──────────────────────────────────────────────────────

    def _load_license(self) -> dict:
        if os.path.exists(LICENSE_FILE):
            try:
                with open(LICENSE_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _save_license(self):
        with open(LICENSE_FILE, "w") as f:
            json.dump(self._license, f, indent=2)

    def _load_usage(self) -> dict:
        if os.path.exists(USAGE_FILE):
            try:
                with open(USAGE_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _save_usage(self):
        with open(USAGE_FILE, "w") as f:
            json.dump(self._usage, f, indent=2)

    def _cleanup_usage(self):
        """Keep only last 3 months of usage data plus _first_use."""
        month_keys = [k for k in self._usage if k != "_first_use"]
        if len(month_keys) > 3:
            sorted_months = sorted(month_keys)
            for old_month in sorted_months[:-3]:
                del self._usage[old_month]

    def _this_month(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m")

    def _mask_key(self) -> str:
        """Mask the license key for display."""
        key = self._license.get("license_key", "")
        if not key:
            return "(none — free tier)"
        # Show first 7 chars and last 4
        if len(key) > 11:
            return key[:7] + "..." + key[-4:]
        return key

    # ── Org Server Sync ─────────────────────────────────────────────────

    @property
    def org_server(self) -> str:
        """Org server URL from env or license file."""
        return os.environ.get("LOCALMASK_SERVER", self._license.get("org_server", ""))

    @property
    def org_name(self) -> str:
        return os.environ.get("LOCALMASK_ORG", self._license.get("org_name", ""))

    def activate_with_org(self, license_key: str, server_url: str, org_name: str = "") -> dict:
        """Activate a license key and register with an org server."""
        # First validate locally
        license_key = license_key.strip()
        if license_key.startswith("LM2."):
            valid, tier, error, payload = _validate_lm2(license_key)
            if valid and not _build_covered(str(payload.get("u", ""))):
                valid, error = False, "License update window predates this version."
        else:
            if not _legacy_keys_ok():
                return {"ok": False, "error": (
                    "This key uses the old format and can no longer be "
                    "activated. Contact hello@localmaskpro.com for a "
                    "replacement key.")}
            valid, tier, error, _expires_at = _validate_key_format(license_key)
        if not valid:
            return {"ok": False, "error": error}

        # Validate with org server (also allocates/enforces a seat).
        try:
            body = json.dumps({"license_key": license_key}).encode()
            req = Request(
                f"{server_url.rstrip('/')}/api/validate",
                data=body,
                headers={"Content-Type": "application/json",
                         "X-License-Key": license_key,
                         "X-Machine-Id": _machine_id(),
                         "X-User-Email": os.environ.get("LOCALMASK_USER_EMAIL", "")},
                method="POST",
            )
            resp = urlopen(req, timeout=10)
            data = json.loads(resp.read())
            if not data.get("valid"):
                return {"ok": False, "error": data.get("error", "Server rejected key")}
        except HTTPError as e:
            try:
                msg = json.loads(e.read()).get("detail", "")
            except Exception:
                msg = ""
            return {"ok": False, "error": msg or f"Server rejected activation ({e.code})"}
        except URLError as e:
            return {"ok": False, "error": f"Cannot reach org server: {e}"}

        now = datetime.now(timezone.utc).isoformat()
        self._license = {
            "license_key": license_key,
            "tier": tier,
            "activated_at": now,
            "last_validated": now,
            "machine_id": _machine_id(),
            "org_server": server_url.rstrip("/"),
            "org_name": org_name or data.get("org", ""),
        }
        if license_key.startswith("LM2."):
            self._license["kind"] = "lm2"
            self._license["updates_until"] = str(payload.get("u", ""))
        self._save_license()
        return {
            "ok": True,
            "tier": tier,
            "tier_name": TIERS[tier]["name"],
            "org_server": self._license["org_server"],
            "org_name": self._license["org_name"],
            "activated_at": now,
        }

    def sync_scan(self, scan_data: dict) -> dict:
        """Sync a scan result to the org server (if connected)."""
        server = self.org_server
        if not server:
            return {"synced": False, "reason": "no org server configured"}
        key = self._license.get("license_key", "")
        if not key:
            return {"synced": False, "reason": "no license key"}
        try:
            payload = json.dumps(scan_data).encode()
            req = Request(
                f"{server}/api/scans/sync",
                data=payload,
                headers={"Content-Type": "application/json", "X-License-Key": key},
                method="POST",
            )
            resp = urlopen(req, timeout=10)
            return json.loads(resp.read())
        except URLError:
            return {"synced": False, "reason": "org server unreachable"}

    def sync_feedback(self, feedback_entries: list) -> dict:
        """Sync model feedback to the org server."""
        server = self.org_server
        if not server:
            return {"synced": False}
        key = self._license.get("license_key", "")
        if not key:
            return {"synced": False}
        try:
            payload = json.dumps({"entries": feedback_entries}).encode()
            req = Request(
                f"{server}/api/feedback/sync",
                data=payload,
                headers={"Content-Type": "application/json", "X-License-Key": key},
                method="POST",
            )
            resp = urlopen(req, timeout=10)
            return json.loads(resp.read())
        except URLError:
            return {"synced": False}
