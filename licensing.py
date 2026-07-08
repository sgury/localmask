"""
LocalMask Pro — License Management & Code Protection.

Offline-first licensing with HMAC-validated keys.
No mandatory phone-home. Free tier works without any key.

License key format: LM-{TIER}-{random_hex(16)}-{checksum_hex(4)}
Storage: ~/.localmask/license.json, ~/.localmask/usage.json
"""
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
from urllib.error import URLError

# ── Constants ────────────────────────────────────────────────────────────────

LICENSE_DIR = os.path.expanduser("~/.localmask")
LICENSE_FILE = os.path.join(LICENSE_DIR, "license.json")
USAGE_FILE = os.path.join(LICENSE_DIR, "usage.json")

# Signing secret for HMAC checksum validation (embedded, not a real secret —
# this is client-side validation only, not meant to be tamper-proof)
_SIGNING_SECRET = b"localmask-pro-2026-offline-license-validation"

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


# ── License Manager ──────────────────────────────────────────────────────────

class LicenseManager:
    """Manages license activation, validation, and usage tracking."""

    def __init__(self):
        os.makedirs(LICENSE_DIR, exist_ok=True)
        self._license = self._load_license()
        self._usage = self._load_usage()

    @property
    def tier(self) -> str:
        """Current tier name. An expired annual license falls back to free
        (offline check, with a short grace window)."""
        tier = self._license.get("tier", "free")
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
        """Activate a license key. Validates format (and expiry) locally."""
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
        if days_left is not None and days_left <= 30:
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
        valid, tier, error, _expires_at = _validate_key_format(license_key)
        if not valid:
            return {"ok": False, "error": error}

        # Validate with org server
        try:
            payload = json.dumps({"license_key": license_key}).encode()
            req = Request(
                f"{server_url.rstrip('/')}/api/validate",
                data=payload,
                headers={"Content-Type": "application/json", "X-License-Key": license_key},
                method="POST",
            )
            resp = urlopen(req, timeout=10)
            data = json.loads(resp.read())
            if not data.get("valid"):
                return {"ok": False, "error": data.get("error", "Server rejected key")}
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
