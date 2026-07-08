"""Persisted user settings — the Web UI writes here, the engine reads.

~/.localmask/settings.json (0600):
  money_mode   off|token|bucket|relative     (Finance Mode default)
  langs        "all" | "none" | "he,ru,..."  (language packs)
  org_lock     {"money_mode": "...", "langs": "..."}  — Team/Ent policy:
               an org admin locks values org-wide; changing a locked value
               requires the admin token (LOCALMASK_ADMIN_TOKEN).

Precedence everywhere: explicit env var > settings file > default. An env
var is a per-invocation decision by the operator and always wins.
"""
import json
import os

_PATH = os.path.expanduser("~/.localmask/settings.json")
_cache = {"mtime": None, "data": {}}


def _read() -> dict:
    try:
        mtime = os.path.getmtime(_PATH)
    except OSError:
        _cache.update(mtime=None, data={})
        return {}
    if _cache["mtime"] != mtime:
        try:
            with open(_PATH, encoding="utf-8") as fh:
                _cache.update(mtime=mtime, data=json.load(fh))
        except (OSError, json.JSONDecodeError):
            _cache.update(mtime=mtime, data={})
    return _cache["data"]


def get_setting(key: str, default=None):
    return _read().get(key, default)


def save_settings(updates: dict) -> dict:
    data = dict(_read())
    data.update(updates)
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    fd = os.open(_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    _cache.update(mtime=None)          # force re-read
    return data


def org_lock() -> dict:
    """Org-wide locked values (Team/Ent policy). Empty dict = no lock."""
    lock = _read().get("org_lock") or {}
    return lock if isinstance(lock, dict) else {}


def admin_token_ok(provided: str) -> bool:
    """True when the caller holds the org admin token. If no token is
    configured, there is no org admin — locking is unavailable."""
    want = os.environ.get("LOCALMASK_ADMIN_TOKEN", "")
    return bool(want) and provided == want
