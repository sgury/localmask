"""Egress policy — the enforcement layer behind Closed Environment mode.

By default this is INERT: LocalMask keeps its normal, already-local behavior and
`assert_host_allowed()` is a no-op. When an org turns on Closed Environment
(Team/Enterprise, org-locked), every outbound host the app is about to contact
is checked against an explicit allowlist and DENIED by default — turning the
"100% local / no phone-home" promise into an enforced lock.

This guards the app's OWN known egress sites (AI providers, git remotes, the
GitHub API, the update check, the org server, Ollama). It is not a network
firewall — pair it with real network egress rules for a hard guarantee.
"""
import os
import re
from urllib.parse import urlparse


class EgressBlocked(RuntimeError):
    """Raised when Closed Environment mode blocks an outbound host."""


# Local services are always reachable (the proxy, a local Ollama, an
# org-server on localhost) — closing the environment is about EXTERNAL egress.
_LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0", ""}


def _truthy(v) -> bool:
    return str(v).strip().lower() not in ("", "0", "false", "no", "off", "none")


def policy() -> dict:
    """Effective closed-env policy. Org lock wins over local settings (so an
    admin can enforce it); `LOCALMASK_CLOSED_ENV` env overrides for CI/testing.
    Returns {closed: bool, allow_hosts: [str], ai_path: 'gateway'|'allowlist'}."""
    try:
        from .settings_store import get_setting, org_lock
        lock = org_lock()
    except Exception:
        lock, get_setting = {}, lambda k, d=None: d

    env = os.environ.get("LOCALMASK_CLOSED_ENV")
    if "closed_env" in lock:
        closed = _truthy(lock["closed_env"])
    elif env is not None:
        closed = _truthy(env)
    else:
        closed = bool(get_setting("closed_env", False))

    allow = lock.get("egress_allowlist")
    if allow is None:
        allow = os.environ.get("LOCALMASK_EGRESS_ALLOWLIST")
    if allow is None:
        allow = get_setting("egress_allowlist", []) or []
    if isinstance(allow, str):
        allow = [h.strip() for h in re.split(r"[,\s]+", allow) if h.strip()]

    ai_path = (lock.get("closed_ai_path")
               or get_setting("closed_ai_path", "gateway"))
    return {"closed": bool(closed),
            "allow_hosts": [h.lower().lstrip("*.") for h in allow],
            "ai_path": ai_path}


def is_closed() -> bool:
    return policy()["closed"]


def ai_egress_mode() -> str:
    """'gateway' = all AI must route through the local proxy / org gateway;
    'allowlist' = direct provider calls allowed, but only to allowlisted hosts."""
    return policy().get("ai_path", "gateway")


def host_of(target: str) -> str:
    """Extract a bare hostname from a URL, a git@host:path, or a host[:port]."""
    t = (target or "").strip()
    if "://" in t:
        return (urlparse(t).hostname or "").lower()
    m = re.match(r"^[\w.-]+@([\w.-]+):", t)      # git@host:org/repo
    if m:
        return m.group(1).lower()
    return t.split("/")[0].split(":")[0].lower()  # host[:port][/path]


def _allowed(host: str, allow: list) -> bool:
    if host in _LOOPBACK:
        return True
    for a in allow:
        if host == a or host.endswith("." + a):
            return True
    return False


def assert_host_allowed(target: str, kind: str = "net") -> str:
    """Deny-by-default egress check. A no-op unless Closed Environment is on.
    Returns the resolved host; raises EgressBlocked when the host is not on the
    allowlist (loopback is always allowed). Blocked attempts are audited."""
    pol = policy()
    host = host_of(target)
    if not pol["closed"] or _allowed(host, pol["allow_hosts"]):
        return host
    try:
        from .audit import audit_event
        audit_event("egress_blocked", ok=False, host=host, kind=kind,
                    target=str(target)[:120])
    except Exception:
        pass
    raise EgressBlocked(
        f"Closed Environment: outbound connection to '{host}' ({kind}) is not "
        f"on the egress allowlist. Ask your admin to allowlist it.")
