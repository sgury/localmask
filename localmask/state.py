"""Shared in-memory state, scan persistence, and scan-record helpers."""
import json
import os
import secrets
import time
from datetime import datetime, timezone


KEYS: dict = {}
SESSIONS: dict = {}   # org_id → session dict
SCANS: dict = {}      # scan_id → ScanRecord (workflow layer)
NOTIFICATIONS: list = []  # {id, scan_id, user, type, message, created_at, read}

APP_CONFIG = {
    "auto_approve_enabled": False,
    "auto_approve_threshold": 0.95,
}

# ── Scan Persistence ───────────────────────────────────────────────────────
# Scans are persisted to disk so they survive process restarts (MCP server
# and FastAPI server are separate processes with separate SCANS dicts).

_SCANS_DIR = os.path.expanduser("~/.localmask/scans")
os.makedirs(_SCANS_DIR, exist_ok=True)


def _get_or_load_scan(scan_id: str) -> dict | None:
    """Get scan from memory, or load from disk if not found."""
    scan = SCANS.get(scan_id)
    if scan:
        return scan
    # Try loading from disk
    path = os.path.join(_SCANS_DIR, f"{scan_id}.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                scan = json.load(f)
            scan.setdefault("session_key", "")
            SCANS[scan_id] = scan
            return scan
        except Exception:
            pass
    return None


def _persist_scan(scan_id: str):
    """Write a scan record to disk."""
    scan = SCANS.get(scan_id)
    if not scan:
        return
    path = os.path.join(_SCANS_DIR, f"{scan_id}.json")
    # Don't persist session_key (references in-memory SESSIONS)
    export = {k: v for k, v in scan.items() if k != "session_key"}
    try:
        with open(path, "w") as f:
            json.dump(export, f, default=str)
    except Exception as e:
        import traceback
        traceback.print_exc()


def _load_persisted_scans():
    """Load all persisted scans from disk into SCANS dict on startup."""
    for fname in os.listdir(_SCANS_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(_SCANS_DIR, fname)
        try:
            with open(path) as f:
                scan = json.load(f)
            scan_id = scan.get("scan_id")
            if scan_id and scan_id not in SCANS:
                # Mark that this scan has no live session (loaded from disk)
                scan.setdefault("session_key", "")
                SCANS[scan_id] = scan
        except Exception:
            pass


# Load persisted scans on module import
_load_persisted_scans()


# ── Session structure ────────────────────────────────────────────────────────
# {
#   "src":          str,              local dir that was scanned
#   "temp":         bool,             whether src is a temp clone
#   "vault":        {value: token},   value  → masked token
#   "rev_vault":    {token: value},   token  → real value
#   "tok_count":    {subtype: int},   per-subtype counter for token naming
#   "files":        {rel: file_dict}, all scanned files
#   "custom_rules": [],               list of {name, pattern, category}
#   "allowed":      set(),            false-positive values to skip
#   "taught":       {value: subtype}, user-taught sensitive values
# }


def _summary(org: str) -> dict:
    s  = SESSIONS[org]
    # Collect unique tokens across all files
    seen_tokens: dict = {}
    for rel, d in s["files"].items():
        for fnd in d["findings"]:
            tok = fnd["token"]
            if not tok:
                continue
            if tok not in seen_tokens:
                seen_tokens[tok] = {**fnd, "file": rel, "count": 0, "files": []}
            seen_tokens[tok]["count"] += 1
            if rel not in seen_tokens[tok]["files"]:
                seen_tokens[tok]["files"].append(rel)

    # Build folder tree
    folders: dict = {}
    for rel, d in sorted(s["files"].items()):
        folder = os.path.dirname(rel) or "."
        folders.setdefault(folder, []).append(
            {"path": rel, "name": os.path.basename(rel),
             "status": d["status"], "findings": d["n"]})

    return {
        "org":          org,
        "tree":         folders,
        "files":        [{"path": p, "status": d["status"], "findings": d["n"]}
                         for p, d in sorted(s["files"].items())],
        "tokens":       [{"token": t, **f} for t, f in sorted(seen_tokens.items())],
        "categories":   s.get("custom_rules", []),
        "active_labels": [],
        "published":    s.get("published", ""),
        "count":        len(seen_tokens),
    }


def _new_session(src: str, temp: bool) -> dict:
    return {
        "src": src, "temp": temp,
        "vault": {}, "rev_vault": {}, "tok_count": {},
        "files": {}, "custom_rules": [], "allowed": set(), "taught": {},
        "published": "",
    }


def _notify(scan_id: str, user: str, ntype: str, message: str):
    NOTIFICATIONS.append({
        "id": f"notif_{secrets.token_hex(8)}",
        "scan_id": scan_id,
        "user": user,
        "type": ntype,
        "message": message,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "read": False,
    })



def _gen_scan_id() -> str:
    return f"scan_{int(time.time())}_{secrets.token_hex(4)}"


def _build_context_lines(content: str, target_line: int, context: int = 5) -> list:
    """Return surrounding lines (masked) around detection, with line numbers."""
    lines = content.split("\n")
    start = max(0, target_line - 1 - context)
    end = min(len(lines), target_line + context)
    result = []
    for i in range(start, end):
        result.append({"lineno": i + 1, "text": lines[i], "is_target": i == target_line - 1})
    return result


def _flatten_detections(session: dict) -> list:
    """Extract all detections from a session, stripping real values.
    Deduplicates by token — same secret found in multiple files becomes
    one detection with a list of all locations."""
    seen_tokens = {}  # token → detection dict
    for rel, fdata in sorted(session["files"].items()):
        content = fdata["masked"]
        for fnd in fdata["findings"]:
            tok = fnd["token"]
            line = fnd.get("line", 0)  # prefer original line from scan
            if not line:
                for j, l in enumerate(content.split("\n"), 1):
                    if tok in l:
                        line = j
                        break

            if tok in seen_tokens:
                # Already seen — just add this file to locations
                det = seen_tokens[tok]
                if rel not in det["files"]:
                    det["files"].append(rel)
                continue

            # Resolve actual value from reverse vault
            real_value = session.get("rev_vault", {}).get(tok, "")

            det = {
                "det_id": None,  # assigned after dedup
                "file": rel,
                "files": [rel],
                "line": line or 1,
                "type": fnd["subtype"],
                "token": tok,
                "value": real_value,
                "confidence": round(fnd.get("confidence", 0.9), 2) if isinstance(fnd.get("confidence"), (int, float)) else 0.9,
                "context_lines": _build_context_lines(content, line or 1),
                "source": fnd.get("engine", "regex"),
                "decision": "pending",
                "llm_decision": fnd.get("llm_decision", ""),
                "llm_confidence": fnd.get("llm_confidence", 0),
                "llm_reason": fnd.get("llm_reason", ""),
            }
            seen_tokens[tok] = det

    # Assign sequential IDs
    detections = list(seen_tokens.values())
    for i, det in enumerate(detections, 1):
        det["det_id"] = f"det_{i:03d}"
    return detections


def _scan_stats(detections: list, session: dict) -> dict:
    by_type = {}
    for d in detections:
        by_type[d["type"]] = by_type.get(d["type"], 0) + 1
    return {
        "total_files": len(session["files"]),
        "total_detections": len(detections),
        "by_type": by_type,
    }


def _scan_to_dict(scan: dict, include_detections: bool = False) -> dict:
    """Serialize a scan record for API response."""
    out = {
        "scan_id": scan["scan_id"],
        "repo_url": scan["repo_url"],
        "org": scan["org"],
        "status": scan["status"],
        "created_at": scan["created_at"],
        "updated_at": scan["updated_at"],
        "submitted_by": scan["submitted_by"],
        "reviewed_by": scan.get("reviewed_by"),
        "review_comment": scan.get("review_comment"),
        "summary_stats": scan["summary_stats"],
        "detection_count": len(scan["detections"]),
        "decisions_made": sum(1 for d in scan["detections"] if d["decision"] != "pending"),
    }
    if include_detections:
        out["detections"] = scan["detections"]
    return out


