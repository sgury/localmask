#!/usr/bin/env python3
"""
LocalMask Pro — MCP Server

Exposes LocalMask secret detection & masking as MCP tools for
Claude Desktop, Cursor, VS Code, and other MCP-compatible clients.

Transport: stdio (local only — no network port, no data leaves your machine)

Run:  python3 mcp_server.py
Or configure in Claude Desktop's settings as an MCP server.
"""
import json
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

from server_core import LocalMaskEngine
from licensing import LicenseManager, generate_license_key

# ── Initialize ───────────────────────────────────────────────────────────────

mcp = FastMCP(
    "LocalMask Pro",
    instructions=(
        "Privacy-first secret detection & masking for code repositories. "
        "Scans repos for credentials, PII, and sensitive data. "
        "All processing happens 100% locally — secrets never leave your machine."
    ),
)

engine = LocalMaskEngine()
license_mgr = LicenseManager()


def _cap_tool(cap: str):
    """Register an MCP tool only when the current edition has the capability.
    In the free edition the function stays defined but is NOT advertised to the
    AI client — so we never expose a tool that can't actually run here."""
    def deco(fn):
        try:
            from localmask._edition import has_capability
            enabled = has_capability(cap)
        except Exception:
            enabled = True
        return mcp.tool()(fn) if enabled else fn
    return deco


# ── Helper ───────────────────────────────────────────────────────────────────

def _gate(action: str):
    """Check license before executing a gated action."""
    license_mgr.check_or_raise(action)


def _safe(fn, *args, **kwargs) -> dict:
    """Call engine method, catch exceptions, return clean dict.
    Strips real secret values from any response to ensure they never
    reach the AI model — only masked tokens are exposed."""
    try:
        result = fn(*args, **kwargs)
        # Strip real values from detections if present
        if isinstance(result, dict) and "detections" in result:
            for det in result["detections"]:
                det.pop("value", None)
        return result
    except KeyError as e:
        return {"error": str(e)}
    except (RuntimeError, ValueError, FileNotFoundError) as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# MCP TOOLS — Actions that LLMs can execute
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def scan_repo(
    source: str,
    sensitivity: str = "standard",
    org: str = "default",
) -> str:
    """Scan a repository for secrets, credentials, and sensitive data.

    Args:
        source: Git URL (https://github.com/org/repo) or local path
        sensitivity: Detection depth — "minimal" (keys/passwords only),
                     "standard" (+ PII, infra), or "strict" (+ org identity, trace IDs)
        org: Organization ID for grouping scans

    Returns scan_id and detection summary. Use get_detections() to see details.
    """
    _gate("scan")
    # Auto-use stored credential for private repos
    credential_id = ""
    try:
        import pathlib
        config_path = pathlib.Path.home() / ".localmask" / "config.json"
        if config_path.exists():
            cfg = json.loads(config_path.read_text())
            credential_id = cfg.get("credential_id", "")
    except Exception:
        pass
    result = _safe(engine.scan_repo, source=source, sensitivity=sensitivity,
                   org=org, credential_id=credential_id)
    license_mgr.record_usage("scan")
    return json.dumps(result, indent=2)


@mcp.tool()
def get_detections(scan_id: str, show_samples: bool = True) -> str:
    """Get detection summary and samples for a scan.

    Returns a summary grouped by type (with counts), plus sample detections
    showing file, line, masked token, and surrounding code context.
    Real secret values are NEVER exposed — only masked tokens like ~[PASSWORD_0]~.

    Args:
        scan_id: Scan ID from scan_repo()
        show_samples: If true, include 2-3 sample detections per type with code context
    """
    result = _safe(engine.get_detections, scan_id)
    if "error" in result:
        return json.dumps(result, indent=2)

    detections = result.get("detections", [])

    # Build summary by type
    from collections import Counter
    type_counts = Counter(d.get("type", "unknown") for d in detections)
    type_summary = [{"type": t, "count": c} for t, c in type_counts.most_common()]

    # Build file summary
    file_counts = Counter(d.get("file", "?") for d in detections)
    file_summary = [{"file": f, "detections": c} for f, c in file_counts.most_common(10)]

    # Build samples: 2 per type, with context lines
    samples = []
    if show_samples:
        seen_types = {}
        for det in detections:
            dtype = det.get("type", "unknown")
            if seen_types.get(dtype, 0) >= 2:
                continue
            seen_types[dtype] = seen_types.get(dtype, 0) + 1
            sample = {
                "det_id": det.get("det_id"),
                "type": dtype,
                "file": det.get("file"),
                "line": det.get("line"),
                "token": det.get("token"),
                "confidence": det.get("confidence"),
                "decision": det.get("decision", "pending"),
            }
            # Include context lines if available
            ctx = det.get("context_lines", [])
            if ctx:
                sample["context"] = "\n".join(
                    f"{'→' if c.get('is_target') else ' '} {c.get('lineno', ''):>4} | {c.get('text', '')}"
                    for c in ctx[:7]
                )
            samples.append(sample)

    output = {
        "scan_id": result.get("scan_id"),
        "status": result.get("status"),
        "repo_url": result.get("repo_url"),
        "total_detections": len(detections),
        "types_found": len(type_counts),
        "files_affected": len(file_counts),
        "by_type": type_summary,
        "top_files": file_summary,
        "samples": samples,
        "all_det_ids": [d.get("det_id") for d in detections],
    }
    return json.dumps(output, indent=2)


@mcp.tool()
def review_detection(
    scan_id: str,
    det_id: str,
    decision: str,
) -> str:
    """Approve or reject a single detection.

    Args:
        scan_id: Scan ID
        det_id: Detection ID (e.g. "det_001")
        decision: "approved" (yes, mask this) or "rejected" (false positive, don't mask)
    """
    if decision not in ("approved", "rejected"):
        return json.dumps({"error": "decision must be 'approved' or 'rejected'"})
    result = _safe(engine.review_detections, scan_id, {det_id: decision})
    return json.dumps(result, indent=2)


@mcp.tool()
def bulk_review(
    scan_id: str,
    decisions: str,
) -> str:
    """Approve or reject multiple detections at once.

    Args:
        scan_id: Scan ID
        decisions: JSON string mapping det_id to decision.
                   Example: '{"det_001": "approved", "det_002": "rejected"}'
    """
    try:
        dec_dict = json.loads(decisions)
    except json.JSONDecodeError:
        return json.dumps({"error": "decisions must be valid JSON"})
    result = _safe(engine.review_detections, scan_id, dec_dict)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_review_queue(scan_id: str) -> str:
    """Get review progress — detection types with counts, confidence, and review status.

    Shows a summary like the CLI's interactive reviewer: each detection type,
    how many are pending vs approved vs rejected, and average confidence.
    Use this to understand what needs review before diving into individual detections.

    Args:
        scan_id: Scan ID from scan_repo()
    """
    result = _safe(engine.get_detections, scan_id)
    if "error" in result:
        return json.dumps(result, indent=2)

    detections = result.get("detections", [])

    # Group by type
    from collections import Counter, defaultdict
    type_groups = defaultdict(list)
    for d in detections:
        type_groups[d.get("type", "unknown")].append(d)

    # Build per-type stats
    types = []
    total_pending = 0
    total_approved = 0
    total_rejected = 0
    for dtype, dets in sorted(type_groups.items(),
                               key=lambda x: -sum(d.get("confidence", 0) for d in x[1]) / len(x[1])):
        pending = sum(1 for d in dets if d.get("decision") in (None, "pending"))
        approved = sum(1 for d in dets if d.get("decision") == "approved")
        rejected = sum(1 for d in dets if d.get("decision") == "rejected")
        avg_conf = sum(d.get("confidence", 0) for d in dets) / len(dets)
        total_pending += pending
        total_approved += approved
        total_rejected += rejected
        files = list(set(d.get("file", "?") for d in dets))

        types.append({
            "type": dtype,
            "total": len(dets),
            "pending": pending,
            "approved": approved,
            "rejected": rejected,
            "avg_confidence": round(avg_conf, 2),
            "files": files[:5],
        })

    output = {
        "scan_id": scan_id,
        "total_detections": len(detections),
        "total_pending": total_pending,
        "total_approved": total_approved,
        "total_rejected": total_rejected,
        "types": types,
        "hint": "Use open_review_ui(scan_id) to launch the interactive terminal reviewer. The developer reviews locally — no tokens, no secrets sent to the cloud.",
    }
    return json.dumps(output, indent=2)


REVIEW_DIR = os.path.expanduser("~/.localmask/reviews")


def _export_scan_for_review(scan_id: str) -> str | None:
    """Write scan detections to a JSON file so the CLI can read them for review."""
    from server import SCANS
    scan = SCANS.get(scan_id)
    if not scan:
        return None

    os.makedirs(REVIEW_DIR, exist_ok=True)
    review_file = os.path.join(REVIEW_DIR, f"{scan_id}.json")

    # Export only what the CLI reviewer needs — no real secret values
    export = {
        "scan_id": scan_id,
        "repo_url": scan.get("repo_url", ""),
        "status": scan.get("status", "draft"),
        "detections": [],
    }
    for d in scan.get("detections", []):
        det_copy = {
            "det_id": d.get("det_id"),
            "type": d.get("type"),
            "file": d.get("file"),
            "line": d.get("line"),
            "token": d.get("token"),
            "confidence": d.get("confidence"),
            "decision": d.get("decision", "pending"),
            "context_lines": d.get("context_lines", []),
            "reason": d.get("reason", ""),
        }
        export["detections"].append(det_copy)

    with open(review_file, "w") as f:
        json.dump(export, f, indent=2, default=str)
    return review_file


def _import_review_decisions(scan_id: str) -> bool:
    """Read review decisions from the file the CLI wrote back."""
    review_file = os.path.join(REVIEW_DIR, f"{scan_id}.json")
    if not os.path.exists(review_file):
        return False

    from server import SCANS
    scan = SCANS.get(scan_id)
    if not scan:
        return False

    with open(review_file) as f:
        reviewed = json.load(f)

    # Build a lookup of decisions from the review file
    file_decisions = {d["det_id"]: d.get("decision", "pending")
                      for d in reviewed.get("detections", [])}

    # Apply decisions back to the in-memory scan
    updated = 0
    for det in scan.get("detections", []):
        file_dec = file_decisions.get(det.get("det_id"))
        if file_dec and file_dec != "pending":
            det["decision"] = file_dec
            updated += 1

    return updated > 0


@_cap_tool("web_ui")
def open_review_ui(scan_id: str) -> str:
    """Launch the interactive detection reviewer in the terminal.

    This opens a local terminal UI where the developer reviews detections
    one by one — approve, reject, edit confidence, see code context.
    NO secrets are sent to the cloud. NO tokens are consumed.
    The review happens entirely in the developer's terminal.

    After the developer finishes reviewing, call sync_review(scan_id)
    to pull their decisions back, then proceed to publish.

    IMPORTANT: Tell the developer to run this command in their terminal:
      localmask review <scan_id>
    Or if localmask is not in PATH:
      ~/.localmask/venv/bin/python3 ~/.localmask/cli.py review <scan_id>

    Args:
        scan_id: Scan ID from scan_repo()
    """
    # Check that the scan exists and has detections
    result = _safe(engine.get_detections, scan_id)
    if "error" in result:
        return json.dumps(result, indent=2)

    detections = result.get("detections", [])
    pending = sum(1 for d in detections if d.get("decision") in (None, "pending"))
    reviewed = len(detections) - pending

    # Export scan to a file so the CLI can read it without needing the FastAPI server
    review_file = _export_scan_for_review(scan_id)

    if not review_file:
        return json.dumps({
            "error": "Could not export scan for review.",
            "scan_id": scan_id,
        }, indent=2)

    # Build the command — use --file mode to read from the export file
    venv_python = os.path.expanduser("~/.localmask/venv/bin/python3")
    cli_path = os.path.expanduser("~/.localmask/cli.py")
    cmd = f"{venv_python} {cli_path} review-local {scan_id}"

    output = {
        "scan_id": scan_id,
        "total_detections": len(detections),
        "pending": pending,
        "already_reviewed": reviewed,
        "review_file": review_file,
        "action": "ASK_DEVELOPER_TO_RUN_IN_TERMINAL",
        "command": cmd,
        "message": (
            f"There are {pending} detections to review. "
            f"Ask the developer to open a terminal and run:\n\n"
            f"  {cmd}\n\n"
            f"This launches an interactive local UI — secrets stay on their machine, "
            f"no tokens are consumed. When they're done, tell me and I'll sync the results back."
        ),
    }
    return json.dumps(output, indent=2)


@mcp.tool()
def sync_review(scan_id: str) -> str:
    """Sync review decisions back from the terminal reviewer.

    Call this AFTER the developer finishes the interactive terminal review
    (localmask review <scan_id>). It pulls their approve/reject decisions
    back so you can proceed to publish.

    Args:
        scan_id: Scan ID that was reviewed in terminal
    """
    synced = _import_review_decisions(scan_id)
    if not synced:
        return json.dumps({
            "error": "No review decisions found. Make sure the developer completed the review in the terminal.",
            "scan_id": scan_id,
        }, indent=2)

    # Now check the updated state
    result = _safe(engine.get_detections, scan_id)
    if "error" in result:
        return json.dumps(result, indent=2)

    detections = result.get("detections", [])
    total = len(detections)
    approved = sum(1 for d in detections if d.get("decision") == "approved")
    rejected = sum(1 for d in detections if d.get("decision") == "rejected")
    pending = total - approved - rejected

    output = {
        "scan_id": scan_id,
        "synced": True,
        "total": total,
        "approved": approved,
        "rejected": rejected,
        "pending": pending,
        "message": (
            f"Review synced: {approved} approved, {rejected} rejected, {pending} pending. "
            + ("Ready to publish!" if pending == 0 else f"{pending} detections still need review.")
        ),
    }
    return json.dumps(output, indent=2)


@mcp.tool()
def get_file_masked(scan_id: str, path: str) -> str:
    """View masked content of a specific file from a scan.

    Args:
        scan_id: Scan ID
        path: Relative file path within the repo (e.g. "src/config.py")
    """
    result = _safe(engine.get_file_masked, scan_id, path)
    return json.dumps(result, indent=2)


@mcp.tool()
def mask_prompt(scan_id: str, text: str) -> str:
    """Mask a question/prompt using this scan's found-secret vault, BEFORE it
    reaches the AI — every known secret becomes a ~[TOKEN]~. Use this when the AI
    reads the masked git repo itself: mask the user's question here, send only
    the masked text, then call rehydrate_answer on the reply. No repo content or
    secrets are sent.

    Args:
        scan_id: Scan ID (its vault defines what gets masked)
        text: The prompt/question to mask
    """
    from localmask.state import _new_session, _get_or_load_scan
    from localmask.masking import _mask_text
    scan = _get_or_load_scan(scan_id)
    if not scan:
        return json.dumps({"error": f"Scan not found: {scan_id}"}, indent=2)
    session = _new_session(scan["repo_url"], temp=False)   # hydrate vault only
    return json.dumps({"masked_text": _mask_text(session, text)}, indent=2)


@mcp.tool()
def rehydrate_answer(scan_id: str, text: str) -> str:
    """Turn ~[TOKEN]~ placeholders in an AI answer back into the real values
    (local, exact, no key). Pair with mask_prompt for the read-from-git flow.

    Args:
        scan_id: Scan ID whose vault to use
        text: The AI's answer containing ~[TOKEN]~ placeholders
    """
    from localmask.state import _new_session, _get_or_load_scan
    from localmask.masking import _rehydrate
    scan = _get_or_load_scan(scan_id)
    if not scan:
        return json.dumps({"error": f"Scan not found: {scan_id}"}, indent=2)
    session = _new_session(scan["repo_url"], temp=False)   # hydrate vault only
    return json.dumps({"text": _rehydrate(session, text)}, indent=2)


@_cap_tool("web_ui")
def submit_for_review(scan_id: str) -> str:
    """Submit a scan for security team approval.

    The scan moves from 'draft' to 'submitted' status.
    If auto-approve is enabled and all detections are high-confidence,
    it may be auto-approved immediately.

    Args:
        scan_id: Scan ID
    """
    result = _safe(engine.submit_scan, scan_id)
    return json.dumps(result, indent=2)


@mcp.tool()
def approve_scan(scan_id: str, reviewer: str = "mcp_user") -> str:
    """Security manager approves the scan. Moves status to 'approved'.

    Args:
        scan_id: Scan ID
        reviewer: Name of the reviewer
    """
    result = _safe(engine.approve_scan, scan_id, reviewer=reviewer)
    return json.dumps(result, indent=2)


@mcp.tool()
def publish_masked_repo(
    scan_id: str,
    target_url: str,
    username: str = "",
    credential_id: str = "",
    private: bool = True,
) -> str:
    """Publish the masked repository to a git remote so an AI/agent can read it.

    All detected secrets are replaced with ~[TOKEN]~ placeholders — the published
    repo has no real secrets. If the remote repo doesn't exist yet it is created
    automatically (GitHub, via a stored token or the `gh` CLI). Grant the AI its
    own read access to that repo; LocalMask never shares your git credentials.

    Args:
        scan_id: Scan ID of a completed scan
        target_url: Target git repo URL (e.g. https://github.com/you/app-masked)
        username: Git username (optional, defaults to x-access-token)
        credential_id: Credential id from `store-token` (optional; else uses gh)
        private: Create the repo private if it must be created (default True)
    """
    # Resolve a locally-stored git token if a credential id was given.
    token = ""
    if credential_id:
        try:
            from localmask.vault_store import get_local_credential
            token = get_local_credential(credential_id) or ""
        except Exception:
            token = ""
    result = _safe(engine.publish_scan, scan_id, target_url,
                   token=token, username=username,
                   create_if_missing=True, private=private,
                   require_approval=True)
    return json.dumps(result, indent=2)


@mcp.tool()
def teach_value(
    scan_id: str,
    value: str,
    action: str = "mask",
    subtype: str = "SECRET",
) -> str:
    """Train the detection model by teaching it about a specific value.

    Args:
        scan_id: Scan ID
        value: The actual string value to teach about
        action: "mask" (this is sensitive, always mask it) or
                "allow" (this is a false positive, don't mask)
        subtype: Type label (e.g. "PASSWORD", "API_KEY", "PERSON_NAME")
    """
    result = _safe(engine.teach_value, scan_id, value, action=action, subtype=subtype)
    return json.dumps(result, indent=2)


@mcp.tool()
def ask_about_scan(
    scan_id: str,
    question: str,
    provider: str = "anthropic",
) -> str:
    """Ask AI to analyze a scanned repository. The AI only sees masked content.

    Great for: security risk assessment, compliance review, understanding
    what types of secrets were found and where.

    Args:
        scan_id: Scan ID
        question: Your question about the scan
        provider: AI provider — "anthropic", "openai", "gemini", or "dry" (test)
    """
    _gate("ask")
    result = _safe(engine.ask_about_scan, scan_id, question, provider=provider)
    license_mgr.record_usage("ask")
    return json.dumps(result, indent=2)


@mcp.tool()
def sync_repo(scan_id: str) -> str:
    """Re-scan a previously scanned repo after git updates.

    Pulls latest code, re-scans for secrets, preserves existing token
    mappings and review decisions. New detections are flagged for review.
    If the scan was published, automatically re-publishes the masked repo.

    Use this after pushing new commits to keep the masked repo in sync.

    Args:
        scan_id: Scan ID of a previously scanned repo
    """
    _gate("scan")
    result = _safe(engine.sync_repo, scan_id)
    license_mgr.record_usage("scan")
    return json.dumps(result, indent=2)


@mcp.tool()
def setup_git_hook(
    repo_path: str,
    scan_id: str,
    hook_type: str = "post-commit",
) -> str:
    """Install a git hook that auto-syncs the masked repo on commits.

    Creates a git hook in the repo that calls `localmask sync` after
    each commit, keeping the masked version up to date.

    Args:
        repo_path: Path to the local git repo
        scan_id: Scan ID to sync on each commit
        hook_type: "post-commit" (after each commit) or "pre-push" (before push)
    """
    import re
    import stat

    if hook_type not in ("post-commit", "pre-push"):
        return json.dumps({"error": "hook_type must be 'post-commit' or 'pre-push'"})

    # scan_id is interpolated into an executable shell script — restrict to
    # the server-generated format so no shell metacharacters can sneak in.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", scan_id):
        return json.dumps({"error": f"Invalid scan_id format: {scan_id!r}"})

    hooks_dir = os.path.join(repo_path, ".git", "hooks")
    if not os.path.isdir(hooks_dir):
        return json.dumps({"error": f"Not a git repo: {repo_path}"})

    hook_path = os.path.join(hooks_dir, hook_type)
    localmask_bin = os.path.expanduser("~/.localmask/localmask")
    mcp_python = os.path.expanduser("~/.localmask/venv/bin/python3")
    cli_path = os.path.expanduser("~/.localmask/cli.py")

    hook_script = f"""#!/bin/bash
# LocalMask Pro — auto-sync masked repo on {hook_type}
# Scan ID: {scan_id}
# Installed: $(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "🔐 LocalMask: syncing masked repo..."

if command -v localmask &>/dev/null; then
    localmask sync {scan_id} 2>&1 | tail -3
elif [ -f "{localmask_bin}" ]; then
    "{localmask_bin}" sync {scan_id} 2>&1 | tail -3
elif [ -f "{mcp_python}" ]; then
    "{mcp_python}" "{cli_path}" sync {scan_id} 2>&1 | tail -3
else
    echo "⚠ LocalMask not found — skipping sync"
fi
"""

    # Don't overwrite existing hooks — append
    if os.path.exists(hook_path):
        with open(hook_path) as f:
            existing = f.read()
        if "LocalMask" in existing:
            return json.dumps({"ok": True, "message": f"Hook already installed in {hook_type}"})
        with open(hook_path, "a") as f:
            f.write("\n" + hook_script)
    else:
        with open(hook_path, "w") as f:
            f.write(hook_script)

    # Make executable
    st = os.stat(hook_path)
    os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    return json.dumps({
        "ok": True,
        "hook": hook_type,
        "repo": repo_path,
        "scan_id": scan_id,
        "message": f"Git {hook_type} hook installed. Masked repo will auto-sync on every {hook_type.replace('-', ' ')}.",
    }, indent=2)


@_cap_tool("learning")
def get_model_stats() -> str:
    """Get statistics about the detection model — learned rules, accuracy, Ollama status."""
    result = _safe(engine.get_model_stats)
    return json.dumps(result, indent=2)


@_cap_tool("learning")
def retrain_model() -> str:
    """Trigger a retrain cycle on accumulated reviewer feedback.

    The model learns from your approve/reject decisions to improve
    future detection accuracy.
    """
    result = _safe(engine.retrain_model)
    return json.dumps(result, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# MCP RESOURCES — Read-only data endpoints
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.resource("localmask://scans")
def resource_scans() -> str:
    """List all scans with summary statistics."""
    scans = engine.list_scans()
    return json.dumps({"scans": scans}, indent=2)


@mcp.resource("localmask://scans/{scan_id}")
def resource_scan(scan_id: str) -> str:
    """Get summary for a specific scan."""
    result = _safe(engine.get_scan, scan_id)
    return json.dumps(result, indent=2)


@mcp.resource("localmask://scans/{scan_id}/files")
def resource_scan_files(scan_id: str) -> str:
    """Get file list with detection counts for a scan."""
    try:
        files = engine.get_file_list(scan_id)
        return json.dumps({"scan_id": scan_id, "files": files}, indent=2)
    except (KeyError, RuntimeError) as e:
        return json.dumps({"error": str(e)})


@mcp.resource("localmask://config")
def resource_config() -> str:
    """Get engine configuration — model info, sensitivity levels."""
    config = engine.get_config()
    return json.dumps(config, indent=2)


@mcp.resource("localmask://license")
def resource_license() -> str:
    """Get current license tier, usage stats, and limits."""
    status = license_mgr.get_status()
    return json.dumps(status, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# LICENSE MANAGEMENT TOOLS
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def activate_license(license_key: str) -> str:
    """Activate a LocalMask Pro license key.

    Args:
        license_key: License key in format LM-{TIER}-{key}-{checksum}
    """
    result = license_mgr.activate(license_key)
    return json.dumps(result, indent=2)


@mcp.tool()
def license_status() -> str:
    """Check current license tier, usage today, and limits."""
    status = license_mgr.get_status()
    return json.dumps(status, indent=2)


@mcp.tool()
def set_api_key(provider: str, key: str) -> str:
    """Set an AI provider API key for the ask_about_scan tool.

    Args:
        provider: "anthropic", "openai", or "gemini"
        key: The API key value
    """
    try:
        engine.set_api_key(provider, key)
        return json.dumps({"ok": True, "provider": provider, "message": f"{provider} key saved"})
    except ValueError as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT TRAIL TOOLS (Enterprise)
# ═══════════════════════════════════════════════════════════════════════════════


@_cap_tool("audit_log")
def audit_trail(limit: int = 20, action: str = "") -> str:
    """Show the tamper-evident audit trail (Enterprise).

    Every scan, sync, review, approve/reject, publish, teach, and ask-AI
    event is recorded — actors, counts, and outcomes, never secret values.

    Args:
        limit: Number of most recent events to return
        action: Filter by action type (scan, sync, review, approve, reject,
                publish, teach, ask_ai) — empty for all
    """
    from localmask.audit import read_events
    events = read_events(limit=limit, action=action)
    return json.dumps({"events": events, "count": len(events)}, indent=2)


@_cap_tool("audit_log")
def audit_export(format: str = "jsonl", out_path: str = "",
                 action: str = "", since: str = "") -> str:
    """Export the audit trail to a file for SIEM/compliance (Enterprise).

    Args:
        format: "jsonl" or "csv"
        out_path: Output file path (default: ~/.localmask/audit/audit-export-<ts>)
        action: Filter by action type — empty for all
        since: Only events at/after this ISO-8601 timestamp
    """
    from localmask.audit import export_audit
    try:
        return json.dumps(export_audit(format, out_path, action, since), indent=2)
    except (ValueError, OSError) as e:
        return json.dumps({"error": str(e)})


@_cap_tool("audit_log")
def audit_verify() -> str:
    """Verify the audit trail's hash chain is intact — proves no record was
    altered or deleted (Enterprise)."""
    from localmask.audit import verify_chain
    return json.dumps(verify_chain(), indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    mcp.run(transport="stdio")
