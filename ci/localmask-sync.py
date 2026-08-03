#!/usr/bin/env python3
"""
LocalMask Pro — CI/CD Sync Agent

Runs in any CI pipeline (GitHub Actions, GitLab CI, Jenkins, etc.).
On every push to the source repo, this script:

  1. Calls the LocalMask server to re-scan the repo
  2. Preserves existing token mappings (PASSWORD_0 stays PASSWORD_0)
  3. Carries over previous review decisions
  4. Publishes the updated masked repo to the target remote
  5. Fails the pipeline if new unreviewed secrets are found (optional)

Environment variables:
  LOCALMASK_SERVER    — LocalMask service URL (required)
  LOCALMASK_KEY       — License key (required for pro/ent)
  SOURCE_REPO         — Source repo URL (default: from git remote)
  MASKED_REPO         — Target masked repo URL (required)
  GIT_TOKEN           — Git PAT for cloning private repos + pushing
  SCAN_ID             — Existing scan ID to sync (auto-detected if omitted)
  SENSITIVITY         — minimal / standard / strict (default: standard)
  FAIL_ON_NEW         — "true" to fail pipeline if new secrets found (default: false)
  ORG                 — Organization ID (default: "default")
  AUTO_APPROVE        — "true" to auto-approve all new detections (default: false)
"""
import json
import os
import sys
import urllib.request
import urllib.error

# ── Config ──────────────────────────────────────────────────────────────────

SERVER = os.environ.get("LOCALMASK_SERVER", "").rstrip("/")
LICENSE_KEY = os.environ.get("LOCALMASK_KEY", "")
SOURCE_REPO = os.environ.get("SOURCE_REPO", "")
MASKED_REPO = os.environ.get("MASKED_REPO", "")
GIT_TOKEN = os.environ.get("GIT_TOKEN", "")
SCAN_ID = os.environ.get("SCAN_ID", "")
SENSITIVITY = os.environ.get("SENSITIVITY", "standard")
FAIL_ON_NEW = os.environ.get("FAIL_ON_NEW", "false").lower() == "true"
ORG = os.environ.get("ORG", "default")
AUTO_APPROVE = os.environ.get("AUTO_APPROVE", "false").lower() == "true"

# Colors for CI logs
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def log(msg, color=""):
    print(f"{color}{msg}{RESET}", flush=True)


def api(method, path, body=None):
    """Call the LocalMask server API."""
    url = f"{SERVER}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if LICENSE_KEY:
        headers["X-License-Key"] = LICENSE_KEY
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode()[:500]
        log(f"API error {e.code}: {err}", RED)
        sys.exit(1)
    except urllib.error.URLError as e:
        log(f"Connection failed: {e.reason}", RED)
        sys.exit(1)


def detect_source_repo():
    """Try to detect source repo from git remote."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ""


def find_existing_scan(source):
    """Find existing scan for this repo."""
    data = api("GET", f"/api/repos?org={ORG}")
    for repo in data.get("repos", []):
        if repo.get("repo_url") == source:
            return repo["scan_id"]
    return ""


def main():
    log(f"\n{BOLD}{'=' * 60}", CYAN)
    log("  LocalMask Pro — CI/CD Sync Agent", CYAN + BOLD)
    log(f"{'=' * 60}{RESET}\n", CYAN)

    # ── Validate config ─────────────────────────────────────────
    if not SERVER:
        log("LOCALMASK_SERVER is required", RED)
        sys.exit(1)
    if not MASKED_REPO:
        log("MASKED_REPO is required (target for masked code)", RED)
        sys.exit(1)

    source = SOURCE_REPO or detect_source_repo()
    if not source:
        log("SOURCE_REPO is required (or run from a git repo)", RED)
        sys.exit(1)

    log(f"  Server:     {SERVER}", DIM)
    log(f"  Source:     {source}", DIM)
    log(f"  Masked to:  {MASKED_REPO}", DIM)
    log(f"  Org:        {ORG}", DIM)
    log("")

    # ── Step 1: Health check ────────────────────────────────────
    log("[1/5] Checking server...", BOLD)
    health = api("GET", "/health")
    if health.get("status") != "ok":
        log("Server health check failed", RED)
        sys.exit(1)
    log(f"  {GREEN}ok{RESET}")

    # ── Step 2: Find or create scan ─────────────────────────────
    log("\n[2/5] Finding scan...", BOLD)
    scan_id = SCAN_ID or find_existing_scan(source)

    if scan_id:
        log(f"  Existing scan: {CYAN}{scan_id}{RESET}")
        log("  Syncing (re-scan with preserved tokens)...")

        body = {}
        if GIT_TOKEN:
            # Store credential first
            cred = api("POST", "/api/credentials", {"token": GIT_TOKEN})
            body["credential_id"] = cred["credential_id"]

        result = api("POST", f"/api/repos/{scan_id}/sync", body)

        total = result.get("total_detections", 0)
        new = result.get("new_detections", 0)
        removed = result.get("removed_detections", 0)
        carried = result.get("carried_decisions", 0)
        pending = result.get("pending_review", 0)

        log(f"\n  {GREEN}Sync complete{RESET}")
        log(f"  Total:    {total} detections")
        if new > 0:
            log(f"  New:      {YELLOW}{BOLD}{new} new secrets found{RESET}")
        if removed > 0:
            log(f"  Removed:  {removed} (no longer in code)")
        log(f"  Carried:  {carried} previous decisions")
        log(f"  Pending:  {pending} need review")
    else:
        log("  No existing scan — creating new scan...")

        body = {
            "repo_url": source,
            "sensitivity": SENSITIVITY,
            "org": ORG,
        }
        if GIT_TOKEN:
            cred = api("POST", "/api/credentials", {"token": GIT_TOKEN})
            body["credential_id"] = cred["credential_id"]

        result = api("POST", "/api/repos/scan", body)
        scan_id = result["scan_id"]
        stats = result.get("summary_stats", {})
        total = stats.get("total_detections", 0)
        new = total
        pending = total

        log(f"\n  {GREEN}Scan complete{RESET}")
        log(f"  Scan ID: {CYAN}{scan_id}{RESET}")
        log(f"  Files:   {stats.get('total_files', 0)}")
        log(f"  Secrets: {RED}{total}{RESET}")

    # ── Step 3: Auto-approve if configured ──────────────────────
    if AUTO_APPROVE and pending > 0:
        log(f"\n[3/5] Auto-approving {pending} detections...", BOLD)
        data = api("GET", f"/api/repos/{scan_id}/detections")
        decisions = {}
        for d in data.get("detections", []):
            if d.get("decision", "pending") == "pending":
                decisions[d["det_id"]] = "approved"
        if decisions:
            api("POST", f"/api/repos/{scan_id}/review", {
                "decisions": decisions, "reviewer": "ci-auto"
            })
            log(f"  {GREEN}Approved {len(decisions)} detections{RESET}")
        pending = 0
    else:
        log("\n[3/5] Review check...", BOLD)
        if pending > 0:
            log(f"  {YELLOW}{pending} detections pending review{RESET}")
        else:
            log(f"  {GREEN}All detections reviewed{RESET}")

    # ── Step 4: Submit + approve scan ───────────────────────────
    log("\n[4/5] Approving scan...", BOLD)
    scan = api("GET", f"/api/repos/{scan_id}")
    status = scan.get("status", "draft")

    if status in ("draft", "rejected"):
        api("POST", f"/api/repos/{scan_id}/submit", {"submitted_by": "ci-pipeline"})
        log("  Submitted for review")

    scan = api("GET", f"/api/repos/{scan_id}")
    status = scan.get("status", "")
    if status in ("submitted", "under_review"):
        api("POST", f"/api/repos/{scan_id}/approve", {
            "reviewer": "ci-pipeline",
            "comment": "Auto-approved by CI/CD pipeline"
        })
        log(f"  {GREEN}Approved{RESET}")
    elif status == "approved":
        log("  Already approved")
    elif status == "published":
        log("  Already published")

    # ── Step 5: Publish masked repo ─────────────────────────────
    log("\n[5/5] Publishing masked repo...", BOLD)

    pub_body = {"target_url": MASKED_REPO}
    if GIT_TOKEN:
        pub_body["token"] = GIT_TOKEN

    result = api("POST", f"/api/repos/{scan_id}/publish", pub_body)

    if result.get("ok"):
        files = result.get("files", "?")
        log(f"  {GREEN}Published! {files} files pushed to:{RESET}")
        log(f"  {CYAN}{MASKED_REPO}{RESET}")
    else:
        log(f"  {RED}Publish failed: {result.get('error', 'unknown')}{RESET}")
        sys.exit(1)

    # ── Summary ─────────────────────────────────────────────────
    log(f"\n{'=' * 60}", GREEN)
    log("  LocalMask CI/CD Sync Complete", GREEN + BOLD)
    log(f"{'=' * 60}\n", GREEN)
    log(f"  Scan ID:    {scan_id}")
    log(f"  Detections: {total}")
    if new > 0:
        log(f"  New:        {new}")
    log(f"  Masked to:  {MASKED_REPO}")
    log("")

    # ── Fail on new secrets if configured ───────────────────────
    if FAIL_ON_NEW and new > 0 and not AUTO_APPROVE:
        log(f"{RED}PIPELINE FAILED: {new} new unreviewed secrets detected.{RESET}")
        log(f"{DIM}Review them at {SERVER} or set AUTO_APPROVE=true{RESET}")
        sys.exit(1)

    # Output for CI systems
    # GitHub Actions
    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"scan_id={scan_id}\n")
            f.write(f"total_detections={total}\n")
            f.write(f"new_detections={new}\n")
            f.write(f"masked_repo={MASKED_REPO}\n")

    log(f"{GREEN}Done.{RESET}\n")


if __name__ == "__main__":
    main()
