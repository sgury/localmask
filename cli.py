#!/usr/bin/env python3
"""
LocalMask Pro CLI — detect, review, and approve secrets in code repos.

The CLI is a thin client that communicates with the LocalMask cloud service.
All scanning and detection happens server-side. Secrets never leave the service.

Usage:
    localmask connect https://localmask-pro-xxx.run.app
    localmask scan https://github.com/org/repo --credential-id cred_xxx
    localmask store-token ghp_xxx                # store token securely, get credential_id
    localmask set-key anthropic sk-ant-xxx       # set AI API key on server
    localmask status                             # list all scans
    localmask status <scan_id>                   # single scan status
    localmask review <scan_id>                   # interactive review via service
    localmask approve-all <scan_id>              # approve all detections + submit
    localmask submit <scan_id>                   # submit for security approval
    localmask publish <scan_id> <target_url>     # publish masked repo to git
    localmask ask <scan_id>                      # interactive AI chat about a scan
    localmask ask <scan_id> "what are the risks" # single question mode
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime

# ── Constants ────────────────────────────────────────────────────────────────
CONFIG_DIR = os.path.expanduser("~/.localmask")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

# ── Colors ───────────────────────────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
UNDERLINE = "\033[4m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
RESET = "\033[0m"


# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE CLIENT — communicates with LocalMask cloud service
# ═══════════════════════════════════════════════════════════════════════════════

class ServiceClient:
    """HTTP client for the LocalMask service API."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _req(self, method: str, path: str, body: dict = None) -> dict:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            err_body = e.read().decode()
            try:
                err = json.loads(err_body)
                raise SystemExit(f"{RED}Error {e.code}: {err.get('error', err_body)}{RESET}")
            except json.JSONDecodeError:
                raise SystemExit(f"{RED}Error {e.code}: {err_body[:200]}{RESET}")
        except urllib.error.URLError as e:
            raise SystemExit(f"{RED}Connection failed: {e.reason}{RESET}")

    def health(self) -> dict:
        return self._req("GET", "/health")

    def store_credential(self, token: str, label: str = "") -> dict:
        return self._req("POST", "/api/credentials", {
            "token": token, "label": label,
        })

    def scan(self, repo_url, credential_id="", org="default",
             sensitivity="standard", submitted_by="developer"):
        return self._req("POST", "/api/repos/scan", {
            "repo_url": repo_url, "credential_id": credential_id, "org": org,
            "sensitivity": sensitivity, "submitted_by": submitted_by,
        })

    def list_repos(self, org=""):
        qs = f"?org={org}" if org else ""
        return self._req("GET", f"/api/repos{qs}")

    def get_scan(self, scan_id):
        return self._req("GET", f"/api/repos/{scan_id}")

    def get_detections(self, scan_id):
        return self._req("GET", f"/api/repos/{scan_id}/detections")

    def post_review(self, scan_id, decisions, reviewer="developer"):
        return self._req("POST", f"/api/repos/{scan_id}/review", {
            "decisions": decisions, "reviewer": reviewer,
        })

    def submit(self, scan_id, submitted_by="developer"):
        return self._req("POST", f"/api/repos/{scan_id}/submit", {
            "submitted_by": submitted_by,
        })

    def ask(self, scan_id, question, provider="anthropic",
            model="claude-sonnet-4-5", source="memory", git_url=""):
        body = {
            "question": question, "provider": provider,
            "model": model, "only_findings": True,
            "source": source,
        }
        if git_url:
            body["git_url"] = git_url
        return self._req("POST", f"/api/repos/{scan_id}/ask", body)

    def ask_reset(self, scan_id):
        return self._req("POST", f"/api/repos/{scan_id}/ask/reset", {})

    def set_key(self, provider: str, key: str) -> dict:
        return self._req("POST", "/api/settings", {provider: key})

    def get_keys(self) -> dict:
        return self._req("GET", "/api/settings")

    def publish(self, scan_id: str, target_url: str,
                token: str = "", credential_id: str = "",
                username: str = "") -> dict:
        body = {"target_url": target_url}
        if credential_id:
            body["credential_id"] = credential_id
        elif token:
            body["token"] = token
        if username:
            body["username"] = username
        return self._req("POST", f"/api/repos/{scan_id}/publish", body)


def _load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def _save_config(cfg: dict):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def _publish_policy() -> str:
    """'review' (default) → publishing/auto-republish needs an approved review.
    'auto' → detections are auto-approved and the masked mirror publishes
    without a manual gate."""
    p = _load_config().get("publish_policy", "review")
    return p if p in ("review", "auto") else "review"


def _pending_count(scan: dict) -> int:
    """Detections not yet decided (approved/rejected) — i.e. unreviewed."""
    return sum(1 for d in scan.get("detections", [])
               if d.get("decision") in (None, "pending"))


def _approve_all_local(scan_id: str) -> dict:
    """Approve every detection and mark the scan approved-for-publish. Returns
    the scan. Used by `approve-all`, by `review` when nothing is left pending,
    and by publish/sync under the 'auto' policy."""
    from server_core import _get_or_load_scan, _persist_scan
    scan = _get_or_load_scan(scan_id)
    if not scan:
        return {}
    for d in scan.get("detections", []):
        if d.get("decision") in (None, "pending"):
            d["decision"] = "approved"
    scan["status"] = "approved"
    scan["reviewed_by"] = scan.get("reviewed_by") or "developer"
    _persist_scan(scan_id)
    return scan


def _is_approved(scan: dict) -> bool:
    return scan.get("status") == "approved" and _pending_count(scan) == 0


def _get_client() -> ServiceClient:
    cfg = _load_config()
    url = cfg.get("service_url")
    if not url:
        raise SystemExit(
            f"{RED}Not connected to a service. Run:{RESET}\n"
            f"  localmask connect <service-url>\n"
        )
    return ServiceClient(url)


def _is_connected() -> bool:
    # The free edition is local-only — never route to a service. This stops a
    # stale service_url (e.g. left over from a prior/Pro install) from hijacking
    # local scans. Pro/Team/Enterprise may still use a hosted server.
    try:
        from localmask._edition import has_capability
        if not has_capability("web_ui"):
            return False
    except Exception:
        pass
    return bool(_load_config().get("service_url"))


def _local_engine():
    """In-process engine — lets scan/status/publish/sync/teach work with no
    server (the free edition ships no web server). Returns a LocalMaskEngine."""
    from server_core import LocalMaskEngine
    return LocalMaskEngine()


def _count_occurrences(src: str, value: str) -> int:
    """How many times the literal value appears across the scanned files —
    the ground truth for 'is this value actually in the code'. Best-effort:
    walks text files under src, skips .git and unreadable/binary files."""
    if not value:
        return 0
    root = src if os.path.isabs(src) else os.path.join(os.getcwd(), src)
    if not os.path.isdir(root):
        return 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > 5_000_000:
                    continue
                with open(fp, "r", errors="ignore") as f:
                    total += f.read().count(value)
            except (OSError, ValueError):
                continue
    return total


def _publish_error_help(err: str, target_url: str, had_token: bool):
    """Turn a git push failure into a clear, actionable message (no traceback)."""
    low = err.lower()
    print(f"  {RED}✗ Publish failed.{RESET}")
    _auth = ("authentication failed", "invalid username or token",
             "password authentication", "403", "could not read username",
             "could not read password", "terminal prompts disabled",
             "authentication required")
    if any(s in low for s in _auth):
        print(f"  {YELLOW}Authentication was rejected by the remote.{RESET}")
        if not had_token:
            print(f"  {DIM}No token was used.{RESET} GitHub/GitLab need a Personal "
                  f"Access Token with {BOLD}repo{RESET} scope to push. Either:")
            print(f"    1) {CYAN}localmask store-token{RESET}   "
                  f"{DIM}(type it hidden → get a credential id){RESET}")
            print(f"       {CYAN}localmask publish <scan> {target_url} -c <cred_id>{RESET}")
            print(f"    2) or a one-off: {CYAN}localmask publish <scan> {target_url} "
                  f"--token <PAT>{RESET} {DIM}(leaks into shell history){RESET}")
        else:
            print(f"  {DIM}The token was rejected — it may be expired, revoked, or "
                  f"missing the {RESET}{BOLD}repo{RESET}{DIM} scope. Create a fresh "
                  f"PAT and store it again with `localmask store-token`.{RESET}")
    elif "not found" in low or "repository not found" in low or "does not exist" in low:
        print(f"  {YELLOW}The target repo doesn't exist yet.{RESET} Create an "
              f"{BOLD}empty{RESET} repo at {CYAN}{target_url}{RESET} first "
              f"(no README), then re-run publish.")
    else:
        print(f"  {DIM}{err[:300]}{RESET}")
    print(f"  {DIM}Nothing was pushed; your secrets never left this machine.{RESET}")


def _print_grant_guide(target_url: str, scan_id: str):
    """Simple next-steps: two ways to let the AI read the masked code. LocalMask
    never hands the AI any credentials."""
    print(f"\n  {BOLD}Two ways to let your AI read the masked code:{RESET}")
    print(f"  {DIM}(It only ever sees ~[TOKEN]~ placeholders — no real secrets.){RESET}\n")
    print(f"  {BOLD}A) The AI reads the published masked git mirror{RESET}")
    print(f"     Give the AI its {BOLD}own{RESET} read access to {CYAN}{target_url}{RESET}")
    print(f"     (read-only collaborator, deploy key, or GitHub/GitLab App), then it")
    print(f"     {BOLD}clones/pulls that repo{RESET} — a copy on the AI's side, separate")
    print(f"     from your real code. LocalMask never shares your git token.")
    print(f"     {DIM}After you change code:{RESET} {CYAN}localmask sync {scan_id}{RESET} "
          f"{DIM}re-masks and{RESET}")
    print(f"     {DIM}re-pushes the mirror (once approved); the AI does{RESET} "
          f"{CYAN}git pull{RESET} {DIM}to get it.{RESET}\n")
    print(f"  {BOLD}B) The AI reads live from LocalMask — nothing published{RESET}")
    print(f"     In your AI editor's MCP config, the assistant calls LocalMask's")
    print(f"     {CYAN}get_detections{RESET} / {CYAN}get_file_masked{RESET} tools. No git repo, no")
    print(f"     pull — LocalMask serves the {BOLD}current{RESET} masked content each call")
    print(f"     (run {CYAN}localmask sync {scan_id}{RESET} {DIM}after code changes so it's fresh).{RESET}")
    print(f"\n  {DIM}The difference:{RESET} (A) the AI holds its own git copy and "
          f"{BOLD}pulls{RESET} to update;")
    print(f"  (B) LocalMask streams the masked files live, always current, no repo.\n")


_ASK_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5", "openai": "gpt-4o", "gemini": "gemini-1.5-pro",
    "grok": "grok-2-latest", "xai": "grok-2-latest", "groq": "llama-3.3-70b-versatile",
    "together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "meta": "meta-llama/Llama-3.3-70B-Instruct-Turbo", "openrouter": "openai/gpt-4o",
}
_ASK_KEY_ENVS = {
    "anthropic": ["ANTHROPIC_API_KEY"], "openai": ["OPENAI_API_KEY"],
    "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY"], "grok": ["XAI_API_KEY"],
    "xai": ["XAI_API_KEY"], "groq": ["GROQ_API_KEY"], "together": ["TOGETHER_API_KEY"],
    "openrouter": ["OPENROUTER_API_KEY"],
}


def _local_ask(args):
    """Bring-your-own-key AI Q&A in the free edition. Masking + rehydration are
    100% local; only masked tokens go to the provider you choose with your key."""
    from localmask.state import _new_session, _get_or_load_scan
    from localmask import ask_local
    scan = _get_or_load_scan(args.scan_id)
    if not scan:
        print(f"{RED}Scan not found: {args.scan_id}{RESET}"); sys.exit(1)

    provider = args.provider.lower()
    # resolve key: --api-key > provider-specific env > generic env > local store
    key = args.api_key
    for env in _ASK_KEY_ENVS.get(provider, []) + ["LOCALMASK_AI_KEY"]:
        if not key:
            key = os.environ.get(env, "")
    if not key and provider != "dry":
        from localmask.vault_store import get_local_ai_key
        key = get_local_ai_key(provider) or ""
    if provider != "dry" and not key:
        envs = " / ".join(_ASK_KEY_ENVS.get(provider, ["LOCALMASK_AI_KEY"]))
        print(f"{RED}No API key for {provider}.{RESET} Save one with "
              f"`localmask set-key {provider}` (stored encrypted, typed hidden), "
              f"or pass --api-key, or set {envs}.")
        sys.exit(1)
    model = args.model or _ASK_DEFAULT_MODELS.get(provider, "gpt-4o")
    question = args.question or "Review this repository and flag the top security risks."

    # rebuild the masked session from source (need masked file contents)
    print(f"  {CYAN}[LOCAL]{RESET} masking repo, asking {provider} ({model}) "
          f"with your key — only masked tokens leave...", flush=True)
    session = _new_session(scan["repo_url"], temp=False)
    from localmask.engine import _scan_dir
    src = scan["repo_url"]
    src = src if os.path.isabs(src) else os.path.join(os.getcwd(), src)
    _scan_dir(session, src)
    if provider == "dry":
        print(f"  {DIM}[dry-run] would ask: {question}{RESET}"); return
    try:
        answer = ask_local.ask(session, question, provider, key, model,
                               base_url=args.base_url)
    except Exception as e:
        print(f"{RED}Ask failed: {e}{RESET}"); sys.exit(1)
    print(f"\n{answer}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION MODEL (remote only — values never leave server)
# ═══════════════════════════════════════════════════════════════════════════════

class Detection:
    """Single detection instance (metadata only — no real secret values)."""
    __slots__ = ("id", "token", "det_type", "line", "confidence",
                 "context_lines", "file", "decision",
                 "confidence_override", "reason", "timestamp")

    def __init__(self, det_id, token, det_type, line, confidence, file,
                 context_lines=None):
        self.id = det_id
        self.token = token
        self.det_type = det_type
        self.line = line
        self.confidence = confidence
        self.context_lines = context_lines or []
        self.file = file
        self.decision = None
        self.confidence_override = None
        self.reason = None
        self.timestamp = None


# ═══════════════════════════════════════════════════════════════════════════════
# HIERARCHICAL REVIEWER — remote service mode only
# ═══════════════════════════════════════════════════════════════════════════════

class HierarchicalReviewer:
    """Interactive 3-level detection reviewer: Type -> Instances -> Single."""

    def __init__(self, detections: list, repo_label: str = "",
                 save_callback=None, repo_root: str = "", mode: str = "SERVICE",
                 teach_callback=None):
        self.repo_label = repo_label
        self.repo_root = repo_root or os.getcwd()
        self.detections = detections
        self._save_callback = save_callback
        self._teach_callback = teach_callback
        self.mode = mode
        self._regroup()

    def _regroup(self):
        """(Re)build the type groupings from self.detections."""
        self.types = {}
        for d in self.detections:
            self.types.setdefault(d.det_type, []).append(d)
        # Sort types by avg confidence (highest first)
        self.type_order = sorted(
            self.types.keys(),
            key=lambda t: -(sum(d.confidence for d in self.types[t]) / len(self.types[t]))
        )

    def _file_link(self, rel_path: str, line: int = 0) -> str:
        """Return clickable file link for VS Code terminal (cmd+click)."""
        # Use relative path — VS Code terminal resolves it against cwd
        return f"./{rel_path}:{line}"

    def _clear(self):
        print("\033[2J\033[H", end="", flush=True)

    def _conf_bar(self, conf, width=18):
        filled = int(conf * width)
        return f"{YELLOW}{'█' * filled}{'░' * (width - filled)}{RESET}"

    def _conf_color(self, conf):
        if conf >= 0.9: return RED
        if conf >= 0.7: return YELLOW
        return DIM

    def _status_icon(self, det):
        if det.decision is True:  return f"{GREEN}✓{RESET}"
        if det.decision is False: return f"{RED}✗{RESET}"
        return f"{DIM}→{RESET}"

    def _input(self, prompt):
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return "q"

    def _save_decisions(self):
        if self._save_callback:
            self._save_callback(self.detections)

    def _teach_missed(self):
        """Prompt for a secret the scanner missed, teach it, and reload the
        detection list so the newly-masked value shows up immediately."""
        self._clear()
        print(f"\n{BOLD}  Teach a missed secret{RESET}\n")
        print(f"  {DIM}Paste the exact value the scanner should have masked "
              f"(blank to cancel).{RESET}\n")
        value = self._input(f"  {BOLD}→ Value: {RESET}")
        if not value:
            return
        subtype = self._input(
            f"  {BOLD}→ Token type{RESET} {DIM}(e.g. API_KEY, PASSWORD; "
            f"default SECRET): {RESET}") or "SECRET"
        print(f"\n  {DIM}Teaching + re-scanning…{RESET}")
        try:
            fresh, hits, added = self._teach_callback(value, subtype)
        except Exception as e:
            print(f"  {RED}✗ Teach failed: {e}{RESET}")
            self._input("  Press Enter to continue...")
            return
        if fresh is not None:
            self.detections = fresh
            self._regroup()
        tok = subtype.upper().replace(" ", "_")
        occ = f"{hits} occurrence" + ("s" if hits != 1 else "")
        if hits and added:
            print(f"  {GREEN}✓ Found {occ} — {added} added to this review, "
                  f"masked as a {tok} token.{RESET}")
        elif hits:
            print(f"  {YELLOW}⚠ Found {occ} in the source, but no new detection "
                  f"was added{RESET} — it may be inside an already-masked secret "
                  f"or in a skipped file.")
        else:
            print(f"  {YELLOW}⚠ Not found in the scanned code{RESET} — "
                  f"check the value (whitespace/quotes?). Saved for future scans.")
        self._input("  Press Enter to continue...")

    # ── LEVEL 1: Type Selection ─────────────────────────────────────────────

    def show_type_summary(self):
        while True:
            self._clear()
            total = len(self.detections)
            reviewed = sum(1 for d in self.detections if d.decision is not None)
            approved = sum(1 for d in self.detections if d.decision is True)
            rejected = sum(1 for d in self.detections if d.decision is False)

            print(f"\n{BOLD}{'═' * 70}{RESET}")
            print(f"{BOLD}  LocalMask Pro — Interactive Review{RESET}  {MAGENTA}[{self.mode}]{RESET}")
            print(f"{BOLD}{'═' * 70}{RESET}")
            print(f"  {DIM}Repo:{RESET}     {self.repo_label}")
            print(f"  {DIM}Total:{RESET}    {total} detections across {len(self.types)} types")
            print(f"  {DIM}Progress:{RESET} {reviewed}/{total}  "
                  f"{GREEN}✓{approved}{RESET}  {RED}✗{rejected}{RESET}  "
                  f"{DIM}→{total - reviewed} pending{RESET}")
            print(f"{BOLD}{'═' * 70}{RESET}\n")

            for i, t in enumerate(self.type_order, 1):
                dets = self.types[t]
                count = len(dets)
                avg_conf = sum(d.confidence for d in dets) / count
                done = sum(1 for d in dets if d.decision is not None)
                bar = self._conf_bar(avg_conf)

                status = ""
                if done == count:
                    status = f" {GREEN}[done]{RESET}"
                elif done > 0:
                    status = f" {YELLOW}[{done}/{count}]{RESET}"

                print(f"  {BOLD}[{i:>2}]{RESET} {CYAN}{t:<30}{RESET} "
                      f"{count:>3} detections  {bar} {avg_conf:.0%}{status}")

            teach_hint = "  [T]each a missed secret" if self._teach_callback else ""
            print(f"\n  {DIM}Navigation: [1-{len(self.type_order)}] select type  "
                  f"[S]ave{teach_hint}  [Q]uit{RESET}")
            print()

            choice = self._input(f"  {BOLD}→ Choose: {RESET}")

            if choice.lower() == "q":
                self._save_decisions()
                where = "locally" if self.mode == "LOCAL" else "to service"
                print(f"\n  {GREEN}✓ Decisions saved {where}{RESET}\n")
                return
            if choice.lower() == "s":
                self._save_decisions()
                print(f"\n  {GREEN}✓ Saved!{RESET}")
                self._input("  Press Enter to continue...")
                continue
            if choice.lower() == "t" and self._teach_callback:
                self._teach_missed()
                continue

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.type_order):
                    self.show_instances(self.type_order[idx])
            except ValueError:
                pass

    # ── LEVEL 2: Instance List ──────────────────────────────────────────────

    def show_instances(self, det_type):
        dets = self.types[det_type]

        while True:
            self._clear()
            count = len(dets)
            done = sum(1 for d in dets if d.decision is not None)
            avg_conf = sum(d.confidence for d in dets) / count

            print(f"\n{BOLD}{'═' * 70}{RESET}")
            print(f"{BOLD}  {det_type}{RESET}  —  {count} detections  "
                  f"avg {avg_conf:.0%} conf  [{done}/{count} reviewed]")
            print(f"{'═' * 70}{RESET}\n")

            print(f"  {DIM}{'#':<4} {'St':>2}  {'File:Line':<38} {'Conf':>5}  Note{RESET}")
            print(f"  {'─' * 64}")

            for i, d in enumerate(dets, 1):
                icon = self._status_icon(d)
                cc = self._conf_color(d.confidence)
                link = self._file_link(d.file, d.line)

                note = ""
                if d.decision is True:
                    note = f"{GREEN}(approved){RESET}"
                elif d.decision is False:
                    note = f"{RED}(rejected){RESET}"
                elif d.confidence < 0.6:
                    note = f"{YELLOW}[LOW!]{RESET}"

                print(f"  {i:<4} {icon}   {link}  "
                      f"{cc}{d.confidence:.0%}{RESET}   {note}")

            print(f"\n  {DIM}Navigation: [J]ump to #  [A]pprove all  [R]eject all  [B]ack{RESET}")
            print()

            choice = self._input(f"  {BOLD}→ Action: {RESET}")

            if choice.lower() in ("b", "q"):
                return
            if choice.lower() == "a":
                for d in dets:
                    if d.decision is None:
                        d.decision = True
                        d.timestamp = datetime.now().isoformat()
                print(f"  {GREEN}✓ Approved all pending in {det_type}{RESET}")
                self._input("  Press Enter to continue...")
                continue
            if choice.lower() == "r":
                for d in dets:
                    if d.decision is None:
                        d.decision = False
                        d.timestamp = datetime.now().isoformat()
                print(f"  {RED}✗ Rejected all pending in {det_type}{RESET}")
                self._input("  Press Enter to continue...")
                continue
            if choice.lower() == "j":
                num = self._input(f"  {BOLD}→ Jump to #: {RESET}")
                try:
                    idx = int(num) - 1
                    if 0 <= idx < len(dets):
                        self.review_instance(dets, idx)
                except ValueError:
                    pass
                continue

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(dets):
                    self.review_instance(dets, idx)
            except ValueError:
                pass

    # ── LEVEL 3: Single Instance Review ─────────────────────────────────────

    def review_instance(self, dets, idx):
        while True:
            if idx < 0:
                idx = 0
            if idx >= len(dets):
                return

            d = dets[idx]
            self._clear()

            icon = self._status_icon(d)
            print(f"\n{BOLD}{'═' * 70}{RESET}")
            print(f"  {BOLD}#{d.det_type}{RESET}  {icon}  "
                  f"{DIM}#{idx + 1}/{len(dets)}{RESET}  —  {CYAN}{d.id}{RESET}")
            print(f"{'═' * 70}{RESET}")
            print(f"  {DIM}File:{RESET}       {self._file_link(d.file, d.line)}")
            print(f"  {DIM}Pattern:{RESET}    {d.det_type}")
            cc = self._conf_color(d.confidence)
            print(f"  {DIM}Confidence:{RESET} {cc}{d.confidence:.0%}{RESET}")
            print()

            self._show_context(d, context_lines=3)

            print(f"\n  {DIM}Will be masked as:{RESET}  {GREEN}{d.token}{RESET}")

            if d.decision is not None:
                status = f"{GREEN}APPROVED{RESET}" if d.decision else f"{RED}REJECTED{RESET}"
                print(f"  {DIM}Current status:{RESET}  {status}")
            if d.reason:
                print(f"  {DIM}Reason:{RESET}  {d.reason}")

            print(f"\n  {DIM}Actions:{RESET}")
            print(f"  {GREEN}[Y]{RESET}es approve   {RED}[N]{RESET}o reject   "
                  f"[E]dit confidence   [R]eason")
            print(f"  [C]ontext expand   "
                  f"[→] Next   [←] Prev   [B]ack")
            print()

            choice = self._input(
                f"  {BOLD}Instance {idx + 1}/{len(dets)} in {d.det_type} → {RESET}"
            )

            if choice.lower() == "y":
                d.decision = True
                d.timestamp = datetime.now().isoformat()
                print(f"  {GREEN}✓ Approved{RESET}")
                idx += 1
                if idx >= len(dets):
                    self._input("  All done in this type! Press Enter...")
                    return
                continue

            if choice.lower() == "n":
                d.decision = False
                d.timestamp = datetime.now().isoformat()
                reason = self._input(f"  {DIM}Reason (optional): {RESET}")
                if reason:
                    d.reason = reason
                print(f"  {RED}✗ Rejected{RESET}")
                idx += 1
                if idx >= len(dets):
                    self._input("  All done in this type! Press Enter...")
                    return
                continue

            if choice.lower() == "e":
                new_conf = self._input(f"  {DIM}New confidence (0-100): {RESET}")
                try:
                    val = int(new_conf) / 100.0
                    if 0 <= val <= 1:
                        d.confidence_override = val
                        d.confidence = val
                        print(f"  {YELLOW}Confidence set to {val:.0%}{RESET}")
                except ValueError:
                    pass
                continue

            if choice.lower() == "r":
                reason = self._input(f"  {DIM}Reason: {RESET}")
                if reason:
                    d.reason = reason
                    print(f"  {DIM}Reason saved{RESET}")
                continue

            if choice.lower() == "c":
                self._clear()
                print(f"\n  {BOLD}{d.file}:{d.line}{RESET}  —  expanded context\n")
                self._show_context(d, context_lines=20)
                self._input("\n  Press Enter to go back...")
                continue

            if choice in ("", "l", "right", "]"):
                idx += 1
                if idx >= len(dets):
                    self._input("  End of list! Press Enter...")
                    return
                continue

            if choice in ("h", "left", "["):
                idx -= 1
                continue

            if choice.lower() in ("b", "q"):
                return

    def _show_context(self, det, context_lines=3):
        """Show source code context from API metadata."""
        max_width = 60

        if not det.context_lines:
            print(f"  {DIM}(no context available){RESET}")
            return

        lines_data = det.context_lines
        print(f"  ┌{'─' * max_width}┐")
        for cl in lines_data:
            lineno = cl["lineno"]
            text = cl["text"]
            if len(text) > max_width - 8:
                text = text[:max_width - 11] + "..."
            if cl.get("is_target"):
                marker = f" {RED}← DETECTED{RESET}"
                print(f"  │{BG_RED}{WHITE}{lineno:>4} │ {text:<{max_width - 7}}{RESET}│{marker}")
            else:
                print(f"  │{DIM}{lineno:>4}{RESET} │ {text:<{max_width - 7}}│")
        print(f"  └{'─' * max_width}┘")

    def run(self):
        """Entry point — start the review."""
        if not self.detections:
            print(f"\n  {GREEN}✓ No detections to review — repo looks clean!{RESET}\n")
            return
        self.show_type_summary()


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

STATUS_COLORS = {
    "draft": DIM, "submitted": YELLOW, "under_review": BLUE,
    "approved": GREEN, "rejected": RED, "published": GREEN,
}

def print_scan_list(repos):
    """Print a table of all scans."""
    print(f"\n{BOLD}{'═' * 80}{RESET}")
    print(f"{BOLD}  LocalMask Pro — Scanned Repositories{RESET}")
    print(f"{BOLD}{'═' * 80}{RESET}\n")

    if not repos:
        print(f"  {DIM}No scans found. Run: localmask scan <repo-url>{RESET}\n")
        return

    print(f"  {DIM}{'Scan ID':<28} {'Status':<14} {'Dets':>5}  {'By':<12} Repo{RESET}")
    print(f"  {'─' * 76}")

    for r in repos:
        sc = STATUS_COLORS.get(r["status"], DIM)
        repo_short = r["repo_url"]
        if len(repo_short) > 30:
            repo_short = "..." + repo_short[-27:]
        print(f"  {r['scan_id']:<28} {sc}{r['status']:<14}{RESET} "
              f"{r['detection_count']:>5}  {r.get('submitted_by', ''):<12} {repo_short}")

    print(f"\n  {DIM}Use: localmask review <scan_id>{RESET}\n")


def print_scan_detail(scan):
    """Print detailed status of a single scan."""
    sc = STATUS_COLORS.get(scan["status"], DIM)

    print(f"\n{BOLD}{'═' * 70}{RESET}")
    print(f"{BOLD}  Scan: {scan['scan_id']}{RESET}")
    print(f"{BOLD}{'═' * 70}{RESET}")
    print(f"  {DIM}Repo:{RESET}        {scan['repo_url']}")
    print(f"  {DIM}Status:{RESET}      {sc}{BOLD}{scan['status'].upper()}{RESET}")
    print(f"  {DIM}Submitted:{RESET}   {scan.get('submitted_by', '-')}")
    print(f"  {DIM}Reviewed:{RESET}    {scan.get('reviewed_by') or '-'}")
    if scan.get("review_comment"):
        print(f"  {DIM}Comment:{RESET}     {scan['review_comment']}")
    print(f"  {DIM}Created:{RESET}     {scan['created_at'][:19]}")

    stats = scan.get("summary_stats", {})
    print(f"\n  {DIM}Files:{RESET}       {stats.get('total_files', 0)}")
    print(f"  {DIM}Detections:{RESET}  {stats.get('total_detections', 0)}")
    print(f"  {DIM}Reviewed:{RESET}    {scan.get('decisions_made', 0)}/{stats.get('total_detections', 0)}")

    by_type = stats.get("by_type", {})
    if by_type:
        print(f"\n  {BOLD}By Type:{RESET}")
        for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
            bar = "█" * min(count * 2, 30)
            print(f"    {t:<30} {count:>3}  {YELLOW}{bar}{RESET}")

    # Status workflow
    steps = ["draft", "submitted", "under_review", "approved"]
    current = scan["status"]
    print(f"\n  {BOLD}Workflow:{RESET}")
    line = "  "
    for i, step in enumerate(steps):
        if step == current:
            line += f" {BG_BLUE}{WHITE} {step.upper()} {RESET}"
        elif steps.index(current) > i if current in steps else False:
            line += f" {GREEN}✓ {step}{RESET}"
        else:
            line += f" {DIM}○ {step}{RESET}"
        if i < len(steps) - 1:
            line += f" {DIM}→{RESET}"
    if current == "rejected":
        line = f"  {RED}✗ REJECTED{RESET}"
    elif current == "published":
        line += f" {DIM}→{RESET} {GREEN}✓ PUBLISHED{RESET}"
    print(line)
    print(f"\n{'═' * 70}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# INIT — set up LocalMask in a repo
# ═══════════════════════════════════════════════════════════════════════════════

def _find_localmask_paths() -> tuple[str, str]:
    """Auto-detect mcp_server.py and python paths."""
    # Check common locations
    candidates = [
        os.path.dirname(os.path.abspath(__file__)),  # same dir as cli.py
        os.path.expanduser("~/.localmask"),
        "/usr/local/lib/localmask",
    ]
    mcp_path = ""
    for d in candidates:
        p = os.path.join(d, "mcp_server.py")
        if os.path.isfile(p):
            mcp_path = p
            break

    python_path = ""
    if mcp_path:
        venv_python = os.path.join(os.path.dirname(mcp_path), "venv", "bin", "python3")
        if os.path.isfile(venv_python):
            python_path = venv_python
    if not python_path:
        python_path = sys.executable

    return mcp_path, python_path


def _gitignore_entries() -> list[str]:
    """Lines to add to .gitignore for LocalMask config files."""
    return [
        "# LocalMask Pro — IDE integration (local only, not published)",
        ".mcp.json",
        "CLAUDE.md",
        ".vscode/mcp.json",
        ".github/copilot-instructions.md",
        "localmask.sh",
    ]


def _ensure_gitignore(repo_dir: str):
    """Add LocalMask entries to .gitignore if not already present."""
    gitignore_path = os.path.join(repo_dir, ".gitignore")
    existing = ""
    if os.path.isfile(gitignore_path):
        existing = open(gitignore_path).read()

    entries = _gitignore_entries()
    to_add = [e for e in entries if e not in existing and not e.startswith("#")]
    # Also check the comment
    if entries[0] not in existing:
        to_add = entries  # add all including the comment

    if not to_add:
        return False  # already present

    with open(gitignore_path, "a") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write("\n".join(to_add) + "\n")
    return True


_CLAUDE_MD_TEMPLATE = """\
# MANDATORY: Use LocalMask MCP Tools

This project has LocalMask Pro configured as an MCP server.

## CRITICAL SECURITY RULES

1. **NEVER read .env, config/settings.py, or any file that may contain secrets directly.** You MUST use the LocalMask MCP tools instead.
2. **NEVER run grep, cat, or any command to search for secrets, passwords, API keys, or credentials.** The MCP tools handle this securely.
3. **NEVER display real secret values.** Only display masked tokens like `~[PASSWORD_0]~`.
4. **ALWAYS use the MCP tools listed below** for any task involving secrets, scanning, reviewing, publishing, or security.

The MCP tools ensure that real secret values NEVER leave this machine. If you read files directly or run grep, you will expose production secrets to the cloud.

## MCP Tools Available

### Scanning
- **`scan_repo`** — Scan for secrets. Use `source: "."` for current repo.
- **`sync_repo`** — Re-scan after git changes. Preserves existing reviews.

### Interactive Review (preferred — runs locally, no tokens consumed)
- **`get_review_queue`** — Overview of all detection types with pending/approved/rejected counts and confidence.
- **`open_review_ui`** — Tells the developer to run the interactive terminal reviewer. No secrets leave the machine.
- **`review_detection`** — Approve or reject one detection by `det_id` (for quick fixes after terminal review).

### Bulk Operations
- **`get_detections`** — Full detection summary with samples (grouped by type).
- **`bulk_review`** — Approve/reject multiple detections at once. Pass `decisions` as JSON string.

### Other
- **`get_file_masked`** — View a file with secrets replaced by tokens.
- **`teach_value`** — Teach a missed secret. Pass `scan_id`, `value`, `action` ("mask"), `subtype`.
- **`submit_for_review`** — Submit scan for security team review.
- **`approve_scan`** — Security manager approves the scan.
- **`publish_masked_repo`** — Push masked repo to git remote. Needs `scan_id`, `target_url`, `username`.
- **`ask_about_scan`** — Ask AI about the code. AI only sees masked content.

## Workflow — ALWAYS follow these steps in order

1. **Scan**: `scan_repo(source=".")` → get `scan_id`
2. **Review queue**: `get_review_queue(scan_id)` → show the developer a summary table of detection types
3. **Interactive review** (in terminal — no tokens, no cloud):
   - Call `open_review_ui(scan_id)` — this gives the developer a terminal command to run
   - Tell the developer to run the command in their terminal
   - The terminal UI lets them approve/reject each detection with full code context
   - When they're done, call `get_review_queue(scan_id)` to check results
   - If the developer spotted a missed secret, use `teach_value` then `sync_repo` to re-scan
4. **Preview**: Use `get_file_masked` on key files to show the developer the masked output.
5. **Publish**: Only after developer confirms → `publish_masked_repo`

**IMPORTANT**: NEVER skip the interactive review. NEVER approve-all and publish in one shot. Show each detection and let the developer decide.

## Privacy Model

- Scanning runs 100% locally (regex + NER + local LLM)
- Real values are stripped from all MCP responses
- AI only sees masked tokens like `~[DB_CONNECTION_URL_3]~`
- Token vault stays on the developer's machine
- `ask_about_scan` responses are rehydrated locally
"""

_COPILOT_MD_TEMPLATE = """\
# LocalMask Pro — Copilot Instructions

## MANDATORY: Use MCP Tools

This project has LocalMask Pro installed as an MCP server. You MUST call the MCP tools directly — NEVER use shell commands, CLI wrappers, or try to scan files yourself.

When the user asks about secrets, scanning, reviewing, publishing, or masking — use the MCP tools listed below. Do NOT run `./localmask.sh`, `python cli.py`, or any shell command as a fallback.

## Tool Quick Reference

| Action | MCP Tool | Required Args |
|--------|----------|---------------|
| Scan repo | `scan_repo` | `source: "."` |
| Review queue overview | `get_review_queue` | `scan_id` |
| Launch terminal reviewer | `open_review_ui` | `scan_id` |
| Approve/reject one | `review_detection` | `scan_id`, `det_id`, `decision` |
| List all detections | `get_detections` | `scan_id` |
| View masked file | `get_file_masked` | `scan_id`, `path` |
| Bulk approve/reject | `bulk_review` | `scan_id`, `decisions` (JSON string) |
| Submit to security team | `submit_for_review` | `scan_id` |
| Publish masked repo | `publish_masked_repo` | `scan_id`, `target_url`, `username` |
| Ask AI about code | `ask_about_scan` | `scan_id`, `question` |
| Re-scan after changes | `sync_repo` | `scan_id` |

## Full Workflow

1. `scan_repo(source=".")` — scan current workspace (100% local)
2. `get_review_queue(scan_id)` — show detection types overview
3. `open_review_ui(scan_id)` → developer reviews in terminal → `get_review_queue()` to check results
4. `submit_for_review(scan_id)` — submit for security team review
5. `publish_masked_repo(scan_id, target_url, username)` — push masked repo
6. `ask_about_scan(scan_id, question)` — AI sees only masked code

## Privacy Architecture

All scanning runs locally. Real values are stripped from all responses.
AI only sees masked tokens. Token vault stays on developer's machine.
"""


def cmd_init(args):
    """Initialize LocalMask in the current repo."""
    repo_dir = os.getcwd()

    # Check if we're in a git repo
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        print(f"  {RED}✗ Not a git repository. Run 'localmask init' from your repo root.{RESET}")
        sys.exit(1)

    # Resolve paths
    mcp_path = args.mcp_path
    python_path = args.python_path
    if not mcp_path or not python_path:
        auto_mcp, auto_python = _find_localmask_paths()
        mcp_path = mcp_path or auto_mcp
        python_path = python_path or auto_python

    if not mcp_path:
        print(f"  {RED}✗ Could not find mcp_server.py. Use --mcp-path to specify.{RESET}")
        sys.exit(1)

    server_url = args.server
    org = args.org
    do_claude = args.claude_code and not args.no_claude_code
    do_copilot = args.copilot and not args.no_copilot
    do_vscode = args.vscode and not args.no_vscode

    print(f"\n  {BOLD}LocalMask Pro — Init{RESET}")
    print(f"  {DIM}Repository:{RESET}  {repo_dir}")
    print(f"  {DIM}MCP server:{RESET}  {mcp_path}")
    print(f"  {DIM}Python:{RESET}      {python_path}")
    print(f"  {DIM}Server URL:{RESET}  {server_url}")
    print(f"  {DIM}Org:{RESET}         {org}")
    print()

    created = []

    # 1. .mcp.json (Claude Code)
    if do_claude:
        mcp_json = {
            "mcpServers": {
                "localmask": {
                    "command": python_path,
                    "args": [mcp_path],
                    "env": {
                        "LOCALMASK_SERVER": server_url,
                        "LOCALMASK_ORG": org,
                    }
                }
            }
        }
        path = os.path.join(repo_dir, ".mcp.json")
        with open(path, "w") as f:
            json.dump(mcp_json, f, indent=2)
            f.write("\n")
        created.append(".mcp.json")

    # 2. CLAUDE.md
    if do_claude:
        path = os.path.join(repo_dir, "CLAUDE.md")
        with open(path, "w") as f:
            f.write(_CLAUDE_MD_TEMPLATE)
        created.append("CLAUDE.md")

    # 3. .vscode/mcp.json
    if do_vscode:
        vscode_dir = os.path.join(repo_dir, ".vscode")
        os.makedirs(vscode_dir, exist_ok=True)
        vscode_mcp = {
            "servers": {
                "localmask": {
                    "type": "stdio",
                    "command": python_path,
                    "args": [mcp_path],
                    "env": {
                        "LOCALMASK_SERVER": server_url,
                        "LOCALMASK_ORG": org,
                    }
                }
            }
        }
        path = os.path.join(vscode_dir, "mcp.json")
        with open(path, "w") as f:
            json.dump(vscode_mcp, f, indent=2)
            f.write("\n")
        created.append(".vscode/mcp.json")

        # Also ensure settings.json has MCP access
        settings_path = os.path.join(vscode_dir, "settings.json")
        settings = {}
        if os.path.isfile(settings_path):
            try:
                settings = json.loads(open(settings_path).read())
            except Exception:
                pass
        if "chat.mcp.access" not in settings:
            settings["chat.mcp.access"] = "all"
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)
                f.write("\n")
            if ".vscode/settings.json" not in created:
                created.append(".vscode/settings.json")

    # 4. .github/copilot-instructions.md
    if do_copilot:
        gh_dir = os.path.join(repo_dir, ".github")
        os.makedirs(gh_dir, exist_ok=True)
        path = os.path.join(gh_dir, "copilot-instructions.md")
        with open(path, "w") as f:
            f.write(_COPILOT_MD_TEMPLATE)
        created.append(".github/copilot-instructions.md")

    # 5. Update .gitignore
    if _ensure_gitignore(repo_dir):
        created.append(".gitignore (updated)")

    # Print results
    for f in created:
        print(f"  {GREEN}✓{RESET} {f}")

    print(f"\n  {GREEN}✓ LocalMask initialized{RESET}")
    print(f"  {DIM}Config files are in .gitignore — they stay local, never published.{RESET}")
    print(f"\n  {BOLD}Next steps:{RESET}")
    print(f"  1. Reload VS Code ({DIM}Cmd+Shift+P → Developer: Reload Window{RESET})")
    print(f"  2. Open the chat panel and ask: {CYAN}Scan this repo for secrets{RESET}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN — command routing
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="localmask",
        description="LocalMask Pro CLI — service client for secret detection and masking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup:
  localmask init                       Initialize LocalMask in current repo
  localmask connect <url>              Connect to LocalMask service
  localmask store-token <token>        Store git token securely, get credential_id
  localmask set-key <provider> <key>   Set AI API key (anthropic, openai, gemini)
  localmask activate <license-key>     Activate a Pro/Enterprise license
  localmask license                    Show current license tier and usage

Workflow:
  localmask scan <repo-url>            Scan repo via service
  localmask status [scan_id]           List scans or show scan detail
  localmask review <scan_id>           Interactive review via service
  localmask submit <scan_id>           Submit for security approval
  localmask approve-all <scan_id>      Approve all detections + submit
  localmask publish <scan_id> <url>    Publish masked repo to a git remote
  localmask ask <scan_id> [question]   Ask AI about a scan (interactive or single question)

Git Integration:
  localmask sync <scan_id>             Re-scan after git updates, preserve tokens
  localmask hook <scan_id> [-r path]   Install git hook for auto-sync on commits

All scanning happens server-side. The CLI never has access to secret values.
The AI only sees masked content — real secrets are replaced with tokens.
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # init
    init_p = sub.add_parser("init", help="Initialize LocalMask in current repo")
    init_p.add_argument("--server", default="http://localhost:8000",
                        help="LocalMask server URL (default: http://localhost:8000)")
    init_p.add_argument("--org", default="my-organization",
                        help="Organization ID (default: my-organization)")
    init_p.add_argument("--mcp-path", default="",
                        help="Path to mcp_server.py (auto-detected if not set)")
    init_p.add_argument("--python-path", default="",
                        help="Path to Python with MCP deps (auto-detected if not set)")
    init_p.add_argument("--claude-code", action="store_true", default=True,
                        help="Generate .mcp.json + CLAUDE.md (default: on)")
    init_p.add_argument("--no-claude-code", action="store_true",
                        help="Skip Claude Code config")
    init_p.add_argument("--copilot", action="store_true", default=True,
                        help="Generate .github/copilot-instructions.md (default: on)")
    init_p.add_argument("--no-copilot", action="store_true",
                        help="Skip Copilot config")
    init_p.add_argument("--vscode", action="store_true", default=True,
                        help="Generate .vscode/mcp.json (default: on)")
    init_p.add_argument("--no-vscode", action="store_true",
                        help="Skip VS Code MCP config")

    # connect
    conn_p = sub.add_parser("connect", help="Connect to LocalMask service")
    conn_p.add_argument("url", help="Service URL (e.g. https://localmask-pro-xxx.run.app)")

    # store-token
    store_p = sub.add_parser("store-token",
                             help="Store a git token (free: encrypted locally; typed hidden)")
    store_p.add_argument("token", nargs="?", default="",
                         help="Git PAT. Omit to type it hidden (recommended — "
                              "an argument leaks into shell history).")
    store_p.add_argument("--label", default="", help="Optional label for this credential")

    # scan
    scan_p = sub.add_parser("scan", help="Scan a repo for secrets")
    scan_p.add_argument("repo_url", help="Git repo URL (https://github.com/org/repo)")
    scan_p.add_argument("--sensitivity", "-s", default="standard",
                        choices=["minimal", "standard", "strict"])
    scan_p.add_argument("--credential-id", "-c", default="",
                        help="Credential ID from store-token (for private repos)")
    scan_p.add_argument("--org", default="default", help="Organization ID")

    # status
    status_p = sub.add_parser("status", help="Show scan status")
    status_p.add_argument("scan_id", nargs="?", help="Scan ID (omit to list all)")
    status_p.add_argument("--org", default="", help="Filter by org")

    # review
    review_p = sub.add_parser("review", help="Interactive hierarchical review")
    review_p.add_argument("scan_id", help="Scan ID from scan command")

    # review-local (reads from file, no HTTP server needed)
    review_local_p = sub.add_parser("review-local",
                                     help="Interactive review from local file (MCP mode)")
    review_local_p.add_argument("scan_id", help="Scan ID from scan command")

    # submit
    submit_p = sub.add_parser("submit", help="Submit scan for security approval")
    submit_p.add_argument("scan_id", help="Scan ID")

    # approve-all
    approve_p = sub.add_parser("approve-all", help="Approve all detections + submit")
    approve_p.add_argument("scan_id", help="Scan ID")

    # set-key
    # config — read/set local settings (e.g. the publish approval policy)
    cfg_p = sub.add_parser("config",
                           help="View or change settings (e.g. publish-policy)")
    cfg_p.add_argument("key", nargs="?", default="",
                       help="Setting name, e.g. publish-policy")
    cfg_p.add_argument("value", nargs="?", default="",
                       help="New value, e.g. review | auto")

    key_p = sub.add_parser("set-key",
                           help="Save an AI provider API key (free: encrypted locally; typed hidden)")
    key_p.add_argument("provider",
                       choices=["anthropic", "openai", "gemini", "grok", "xai",
                                "groq", "together", "meta", "openrouter"],
                       help="AI provider name")
    key_p.add_argument("key", nargs="?", default="",
                       help="API key. Omit to type it hidden (recommended — an "
                            "argument leaks into shell history).")

    # teach — add a secret the scanner missed (or ignore a false positive),
    #         persisted so it applies on every future scan/sync of this repo.
    teach_p = sub.add_parser(
        "teach", help="Teach a missed secret (or ignore a false positive)")
    teach_p.add_argument("scan_id", help="Scan ID to apply the value to")
    teach_p.add_argument("value", help="The exact secret value the scanner missed")
    teach_p.add_argument("--subtype", "-s", default="SECRET",
                         help="Token type/name for the masked value (e.g. API_KEY)")
    teach_p.add_argument("--allow", action="store_true",
                        help="Instead of masking, mark this value as a false "
                             "positive (never mask it)")

    # publish
    pub_p = sub.add_parser("publish", help="Publish masked repo to a git remote")
    pub_p.add_argument("scan_id", help="Scan ID of an approved scan")
    pub_p.add_argument("target_url", help="Target git repo URL to push masked code to")
    pub_p.add_argument("--token", "-t", default="",
                       help="Git PAT for pushing (or use --credential-id)")
    pub_p.add_argument("--credential-id", "-c", default="",
                       help="Credential ID from store-token")
    pub_p.add_argument("--username", "-u", default="", help="Git username")
    pub_p.add_argument("--force", "-f", action="store_true",
                       help="Publish even if the review isn't approved (one-off)")

    # activate
    act_p = sub.add_parser("activate", help="Activate a LocalMask Pro license key")
    act_p.add_argument("license_key", help="License key (format: LM-TIER-key-checksum)")

    # license
    sub.add_parser("license", help="Show current license tier and usage")

    # sync
    sync_p = sub.add_parser("sync", help="Re-scan repo after git updates, preserve tokens & decisions")
    sync_p.add_argument("scan_id", help="Scan ID of a previously scanned repo")
    sync_p.add_argument("--credential-id", "-c", default="", help="Credential ID for private repos")

    # hook
    hook_p = sub.add_parser("hook", help="Install git hook for auto-sync on commits")
    hook_p.add_argument("scan_id", help="Scan ID to sync on each commit")
    hook_p.add_argument("--repo", "-r", default=".", help="Path to git repo (default: current dir)")
    hook_p.add_argument("--type", "-t", default="post-commit",
                        choices=["post-commit", "pre-push"],
                        help="Hook type (default: post-commit)")

    # ask
    ask_p = sub.add_parser("ask", help="Ask any AI about a scan (masked content only, your key)")
    ask_p.add_argument("scan_id", help="Scan ID to ask about")
    ask_p.add_argument("question", nargs="?", default="",
                       help="Question (omit for interactive mode)")
    ask_p.add_argument("--provider", "-p", default="anthropic",
                       help="anthropic | openai | gemini | grok | groq | together | meta | openrouter | dry")
    ask_p.add_argument("--api-key", "-k", default="",
                       help="Your provider API key (or env: LOCALMASK_AI_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / XAI_API_KEY)")
    ask_p.add_argument("--base-url", default="",
                       help="Custom OpenAI-compatible endpoint (self-host, OpenRouter, etc.)")
    ask_p.add_argument("--model", "-m", default="",
                       help="Model name (defaults per provider)")
    ask_p.add_argument("--source", "-s", default="memory",
                       choices=["memory", "git"],
                       help="Read from platform memory (default) or published masked git repo")
    ask_p.add_argument("--git-url", default="",
                       help="Git URL of published masked repo (for --source git)")

    # Local, no-key: turn an AI's tokenized answer back into real values.
    rehy_p = sub.add_parser("rehydrate",
                            help="Rehydrate ~[TOKEN]~ back to real values (local, no AI key)")
    rehy_p.add_argument("scan_id", help="Scan ID whose vault to use")
    rehy_p.add_argument("file", nargs="?", default="",
                        help="File to rehydrate (default: read stdin)")

    maskt_p = sub.add_parser("mask-text",
                             help="Mask secrets in arbitrary text using a scan's vault (local)")
    maskt_p.add_argument("scan_id", help="Scan ID whose vault to use")
    maskt_p.add_argument("file", nargs="?", default="",
                         help="File to mask (default: read stdin)")

    exp_p = sub.add_parser("export",
                           help="Write the masked repo to a local folder the AI can read (no keys/permissions)")
    exp_p.add_argument("scan_id", help="Scan ID to export")
    exp_p.add_argument("output_dir", help="Folder to write masked files into")

    proxy_p = sub.add_parser("proxy",
                             help="Run the local AI proxy (prompt firewall, Pro)")
    proxy_p.add_argument("--port", type=int, default=None,
                         help="Listen port (default 8100 or proxy.yaml)")
    proxy_p.add_argument("--use-model", action="store_true",
                         help="Use the local AI model for masking (higher recall, slower)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "proxy":
        if args.port:
            os.environ["LOCALMASK_PROXY_PORT"] = str(args.port)
        if getattr(args, "use_model", False):
            os.environ["LOCALMASK_PROXY_USE_MODEL"] = "true"
        try:
            from localmask.proxy import main as proxy_main
        except ImportError:
            print("The AI proxy is a Pro feature and isn't included in this "
                  "edition.\nUpgrade at https://localmaskpro.com")
            sys.exit(1)
        proxy_main()
        return

    # ── rehydrate (local, no key) ────────────────────────────────────────────
    if args.command == "rehydrate":
        from localmask.state import _new_session, _get_or_load_scan
        from localmask.masking import _rehydrate
        scan = _get_or_load_scan(args.scan_id)
        if not scan:
            print(f"{RED}Scan not found: {args.scan_id}{RESET}"); sys.exit(1)
        session = _new_session(scan["repo_url"], temp=False)  # hydrates vault
        text = open(args.file).read() if args.file else sys.stdin.read()
        sys.stdout.write(_rehydrate(session, text))
        return

    # ── mask-text (local) ────────────────────────────────────────────────────
    if args.command == "mask-text":
        from localmask.state import _new_session, _get_or_load_scan
        from localmask.engine import _scan_file
        scan = _get_or_load_scan(args.scan_id)
        if not scan:
            print(f"{RED}Scan not found: {args.scan_id}{RESET}"); sys.exit(1)
        session = _new_session(scan["repo_url"], temp=False)
        text = open(args.file).read() if args.file else sys.stdin.read()
        sys.stdout.write(_scan_file(session, text, "input.txt")["masked"])
        return

    # ── export masked repo to a local folder (AI reads it, no keys) ──────────
    if args.command == "export":
        from localmask.state import _new_session, _get_or_load_scan
        from localmask.engine import _scan_dir
        from localmask.gitops import _should_publish
        scan = _get_or_load_scan(args.scan_id)
        if not scan:
            print(f"{RED}Scan not found: {args.scan_id}{RESET}"); sys.exit(1)
        session = _new_session(scan["repo_url"], temp=False)
        src = scan["repo_url"]
        src = src if os.path.isabs(src) else os.path.join(os.getcwd(), src)
        _scan_dir(session, src)
        out = os.path.expanduser(args.output_dir)
        written = 0
        for rel, d in session["files"].items():
            if not _should_publish(rel):
                continue
            path = os.path.join(out, rel)
            os.makedirs(os.path.dirname(path) or out, exist_ok=True)
            with open(path, "w") as f:
                f.write(d["masked"])
            written += 1
        print(f"  {GREEN}✓ Exported {written} masked files to {out}{RESET}")
        print(f"  {DIM}Point your AI tool / agent at this folder — it reads the "
              f"masked code with no keys, no repo permissions, no secrets.{RESET}")
        return

    # ── ask (local, bring-your-own-key, any provider) ────────────────────────
    if args.command == "ask" and not _is_connected():
        _local_ask(args)
        return

    # ── hosted-only commands: give a clear local-mode message (not a raw
    #    "not connected" error) plus the free-edition alternative. ────────────
    if args.command == "store-token" and not _is_connected():
        import getpass
        token = (args.token or "").strip()
        if not token or token == "-":
            try:
                token = getpass.getpass("  Paste git token (hidden): ").strip()
            except (EOFError, KeyboardInterrupt):
                token = ""
        if not token:
            print(f"  {RED}✗ No token provided.{RESET}")
            return
        from localmask.vault_store import store_local_credential
        cid = store_local_credential(token, args.label or "")
        print(f"  {GREEN}✓ Stored (encrypted, local — 0600 SQLite){RESET}")
        print(f"  {DIM}Credential ID:{RESET} {CYAN}{cid}{RESET}")
        print(f"  {DIM}Use it:{RESET} localmask publish <scan> <url> -c {cid}")
        print(f"  {DIM}or:{RESET}     localmask scan <private-url> -c {cid}")
        if token.startswith("ghp_") and args.token:
            print(f"  {YELLOW}⚠ You passed the token on the command line — it's "
                  f"now in your shell history.{RESET} Run store-token with no "
                  f"argument next time so it's typed hidden; and rotate this one.")
        return

    # set-key (free): store the AI provider key encrypted locally so `ask`
    # reuses it. Typed hidden so it never lands in shell history.
    if args.command == "set-key" and not _is_connected():
        import getpass
        provider = args.provider.lower()
        key = (args.key or "").strip()
        passed_as_arg = bool(key)
        if not key or key == "-":
            try:
                key = getpass.getpass(f"  Paste {provider} API key (hidden): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
        if not key:
            print(f"  {RED}✗ No key provided.{RESET}")
            return
        from localmask.vault_store import set_local_ai_key
        set_local_ai_key(provider, key)
        print(f"  {GREEN}✓ Saved {provider} key (encrypted, local — 0600 SQLite){RESET}")
        print(f"  {DIM}Use it:{RESET} localmask ask <scan> \"...\" --provider {provider}")
        if passed_as_arg:
            print(f"  {YELLOW}⚠ You passed the key on the command line — it's now "
                  f"in your shell history.{RESET} Run `set-key {provider}` with no "
                  f"key next time (typed hidden), and rotate this one.")
        return

    # config (local): view or set settings, e.g. the publish approval policy.
    if args.command == "config":
        key = (args.key or "").replace("-", "_")
        if not key:
            cfg = _load_config()
            print(f"  {BOLD}Settings{RESET} {DIM}({CONFIG_FILE}){RESET}")
            print(f"    publish-policy = {CYAN}{_publish_policy()}{RESET}  "
                  f"{DIM}(review = approve before publishing · auto = "
                  f"auto-approve + auto-publish){RESET}")
            return
        if key == "publish_policy":
            val = (args.value or "").lower()
            if val not in ("review", "auto"):
                print(f"  {RED}✗ publish-policy must be 'review' or 'auto'.{RESET}")
                return
            cfg = _load_config(); cfg["publish_policy"] = val; _save_config(cfg)
            print(f"  {GREEN}✓ publish-policy = {val}{RESET}")
            if val == "auto":
                print(f"  {DIM}Detections auto-approve; sync/hook auto-republish "
                      f"the masked mirror on every change.{RESET}")
            else:
                print(f"  {DIM}Publishing now requires an approved review "
                      f"(localmask review / approve-all).{RESET}")
            return
        print(f"  {RED}✗ Unknown setting '{args.key}'.{RESET} Known: publish-policy")
        return

    # approve-all (local): approve every detection and mark the scan approved,
    # so it can be published under the 'review' policy.
    if args.command == "approve-all" and not _is_connected():
        from server_core import _get_or_load_scan
        if not _get_or_load_scan(args.scan_id):
            print(f"  {RED}✗ Scan not found: {args.scan_id}{RESET}")
            return
        scan = _approve_all_local(args.scan_id)
        n = len(scan.get("detections", []))
        print(f"  {GREEN}✓ Approved all {n} detections{RESET} — scan is "
              f"{BOLD}approved{RESET} and ready to publish.")
        print(f"  {DIM}Publish:{RESET} localmask publish {args.scan_id} <git-url>")
        return

    if args.command == "submit" and not _is_connected():
        _hint = {
            "submit":      "The submit/approval workflow is a hosted "
                           "(Pro/Team) feature. In free, approve locally with "
                           "`localmask review <scan>` or `localmask approve-all "
                           "<scan>`.",
        }[args.command]
        print(f"  {YELLOW}'{args.command}' needs the hosted service "
              f"(Pro/Team).{RESET}\n  {_hint}")
        return

    # ── connect ─────────────────────────────────────────────────────────────
    if args.command == "init":
        cmd_init(args)

    elif args.command == "connect":
        url = args.url.rstrip("/")
        print(f"  {DIM}Connecting to {url}...{RESET}", flush=True)
        client = ServiceClient(url)
        resp = client.health()
        if resp.get("status") == "ok":
            _save_config({"service_url": url})
            print(f"  {GREEN}✓ Connected to LocalMask service{RESET}")
            print(f"  {DIM}Saved to {CONFIG_FILE}{RESET}\n")
        else:
            print(f"  {RED}✗ Service responded but health check failed{RESET}\n")

    # ── store-token ─────────────────────────────────────────────────────────
    elif args.command == "store-token":
        client = _get_client()
        print(f"  {DIM}Storing credential on service...{RESET}", flush=True)
        result = client.store_credential(args.token, args.label)
        cred_id = result["credential_id"]
        expires = result.get("expires_in", "1 hour")

        # Save credential_id locally for convenience
        cfg = _load_config()
        cfg["credential_id"] = cred_id
        _save_config(cfg)

        print(f"  {GREEN}✓ Token stored securely{RESET}")
        print(f"  {DIM}Credential ID:{RESET}  {CYAN}{cred_id}{RESET}")
        print(f"  {DIM}Expires in:{RESET}     {expires}")
        print(f"  {DIM}Saved to:{RESET}       {CONFIG_FILE}")
        print(f"\n  {DIM}Use with scan:{RESET}")
        print(f"    localmask scan <repo-url> -c {cred_id}")
        print(f"    localmask scan <repo-url>  {DIM}(auto-uses saved credential){RESET}\n")

    # ── scan ────────────────────────────────────────────────────────────────
    elif args.command == "scan":
        # Local, in-process scan (no server needed) — the default for the free
        # edition. Used whenever not connected to a service, or the target is a
        # local directory.
        if not _is_connected() or os.path.isdir(os.path.expanduser(args.repo_url)):
            print(f"\n  {CYAN}[LOCAL]{RESET} Scanning on this machine "
                  f"(nothing leaves your computer)...", flush=True)
            eng = _local_engine()
            # Private remote? Resolve a locally-stored credential into a token.
            token = ""
            if args.credential_id:
                from localmask.vault_store import get_local_credential
                token = get_local_credential(args.credential_id) or ""
                if not token:
                    print(f"  {RED}✗ Unknown credential id "
                          f"'{args.credential_id}'.{RESET} Run "
                          f"`localmask store-token` first.")
                    return
            try:
                result = eng.scan_repo(
                    source=os.path.expanduser(args.repo_url),
                    sensitivity=args.sensitivity, org=args.org, token=token)
            except Exception as e:
                print(f"  {RED}✗ Scan failed:{RESET} {str(e)[:300]}")
                if "clone failed" in str(e).lower() or "authentication" in str(e).lower():
                    print(f"  {DIM}For a private repo, add a token: "
                          f"localmask store-token → scan <url> -c <cred_id>.{RESET}")
                return
            scan_id = result["scan_id"]
            stats = result.get("summary_stats", {})
            print(f"  {GREEN}✓ Scan complete{RESET}\n")
            print(f"  {BOLD}Scan ID:{RESET}     {CYAN}{scan_id}{RESET}")
            print(f"  {DIM}Files:{RESET}       {stats.get('total_files', 0)}")
            print(f"  {DIM}Detections:{RESET}  {RED}{stats.get('total_detections', 0)}{RESET}")
            by_type = stats.get("by_type", {})
            if by_type:
                print(f"\n  {BOLD}By type:{RESET}")
                for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
                    print(f"    {t:28s} {RED}{count}{RESET}")
            print(f"\n  {DIM}Next:{RESET} localmask status  ·  "
                  f"localmask publish {scan_id} --target <git-url>")
            return

        client = _get_client()

        # Resolve credential_id: explicit flag > saved config
        cred_id = args.credential_id
        if not cred_id:
            cred_id = _load_config().get("credential_id", "")

        print(f"\n  {MAGENTA}[SERVICE]{RESET} Scanning via cloud service...", flush=True)
        if cred_id:
            print(f"  {DIM}Using credential:{RESET} {cred_id}")

        result = client.scan(
            repo_url=args.repo_url, credential_id=cred_id,
            org=args.org, sensitivity=args.sensitivity,
        )
        scan_id = result["scan_id"]
        stats = result.get("summary_stats", {})

        print(f"  {GREEN}✓ Scan complete{RESET}\n")
        print(f"  {BOLD}Scan ID:{RESET}     {CYAN}{scan_id}{RESET}")
        print(f"  {DIM}Files:{RESET}       {stats.get('total_files', 0)}")
        print(f"  {DIM}Detections:{RESET}  {RED}{stats.get('total_detections', 0)}{RESET}")
        print(f"  {DIM}Status:{RESET}      draft")

        by_type = stats.get("by_type", {})
        if by_type:
            print(f"\n  {BOLD}By Type:{RESET}")
            for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
                bar = "█" * min(count * 2, 30)
                print(f"    {t:<30} {count:>3}  {YELLOW}{bar}{RESET}")

        print(f"\n  {DIM}Next steps:{RESET}")
        print(f"    localmask review {scan_id}")
        print(f"    localmask approve-all {scan_id}")
        print(f"    localmask submit {scan_id}\n")

    # ── status ──────────────────────────────────────────────────────────────
    elif args.command == "status":
        if not _is_connected():
            eng = _local_engine()
            if args.scan_id:
                print_scan_detail(eng.get_scan(args.scan_id))
            else:
                scans = eng.list_scans(args.org)
                if not scans:
                    print(f"  {DIM}No local scans yet. Run: localmask scan <path>{RESET}")
                for s in scans:
                    print(f"  {CYAN}{s['scan_id']}{RESET}  {s.get('repo_url','')}  "
                          f"{RED}{s.get('detection_count', 0)}{RESET} detections")
            return
        client = _get_client()
        if args.scan_id:
            scan = client.get_scan(args.scan_id)
            print_scan_detail(scan)
        else:
            data = client.list_repos(args.org)
            print_scan_list(data.get("repos", []))

    # ── review ──────────────────────────────────────────────────────────────
    elif args.command == "review":
        scan_id = args.scan_id
        if not _is_connected():
            eng = _local_engine()

            def _load_dets():
                data = eng.get_detections(scan_id)
                out = []
                for d in data.get("detections", []):
                    det = Detection(
                        det_id=d["det_id"], token=d["token"], det_type=d["type"],
                        line=d.get("line", 0), confidence=d.get("confidence", 0.9),
                        file=d.get("file", ""),
                        context_lines=d.get("context_lines", []))
                    if d.get("decision") == "approved":
                        det.decision = True
                    elif d.get("decision") == "rejected":
                        det.decision = False
                    out.append(det)
                return data.get("repo_url", scan_id), out

            repo_url, dets = _load_dets()
            print(f"  {GREEN}✓ {len(dets)} detections loaded (local){RESET}\n")

            def save_local(detections):
                decisions = {det.id: ("approved" if det.decision else "rejected")
                             for det in detections if det.decision is not None}
                if decisions:
                    eng.review_detections(scan_id, decisions)
                    print(f"  {GREEN}✓ Saved {len(decisions)} decisions locally{RESET}")
                # If every detection has now been decided, mark the scan approved
                # so it can be published under the 'review' policy.
                from server_core import _get_or_load_scan, _persist_scan
                sc = _get_or_load_scan(scan_id)
                if sc:
                    pend = _pending_count(sc)
                    if pend == 0 and sc.get("detections"):
                        sc["status"] = "approved"
                        sc["reviewed_by"] = "developer"
                        _persist_scan(scan_id)
                        print(f"  {GREEN}✓ All reviewed — scan approved for "
                              f"publish.{RESET}")
                    elif pend:
                        print(f"  {YELLOW}{pend} still pending{RESET} — approve "
                              f"them (or `localmask approve-all {scan_id}`) "
                              f"before publishing.")

            def teach_local(value, subtype):
                # Persist to the repo lexicon, then re-scan in place so the
                # newly-masked value appears. Returns (refreshed_dets, hits,
                # added) — hits = occurrences in the code, added = new detections.
                from server_core import _get_or_load_scan
                from localmask.vault_store import get_vault_store, repo_id_for
                sc = _get_or_load_scan(scan_id)
                src = sc.get("repo_url", "") if sc else ""
                hits = _count_occurrences(src, value)
                get_vault_store(repo_id_for(src)).set_lexicon(
                    value, action="mask", subtype=subtype)
                added = 0
                if hits:
                    added = eng.sync_repo(
                        scan_id, auto_republish=False).get("new_detections", 0)
                _, fresh = _load_dets()
                return fresh, hits, added

            HierarchicalReviewer(dets, repo_url, save_callback=save_local,
                                 mode="LOCAL", teach_callback=teach_local).run()
            return

        client = _get_client()
        print(f"\n  {MAGENTA}[SERVICE]{RESET} Fetching detections for {scan_id}...", flush=True)
        data = client.get_detections(scan_id)
        repo_url = data.get("repo_url", scan_id)

        dets = []
        for d in data["detections"]:
            det = Detection(
                det_id=d["det_id"], token=d["token"],
                det_type=d["type"], line=d["line"],
                confidence=d["confidence"], file=d["file"],
                context_lines=d.get("context_lines", []),
            )
            if d.get("decision") == "approved":
                det.decision = True
            elif d.get("decision") == "rejected":
                det.decision = False
            dets.append(det)

        print(f"  {GREEN}✓ {len(dets)} detections loaded{RESET}\n")

        def save_to_service(detections):
            decisions = {}
            for det in detections:
                if det.decision is not None:
                    decisions[det.id] = "approved" if det.decision else "rejected"
            if decisions:
                result = client.post_review(scan_id, decisions)
                print(f"  {GREEN}✓ Synced {result.get('updated', 0)} decisions to service{RESET}")

        reviewer = HierarchicalReviewer(
            dets, repo_url, save_callback=save_to_service
        )
        reviewer.run()

    # ── review-local (file-based, no HTTP server needed) ─────────────────
    elif args.command == "review-local":
        scan_id = args.scan_id
        review_dir = os.path.expanduser("~/.localmask/reviews")
        review_file = os.path.join(review_dir, f"{scan_id}.json")

        if not os.path.exists(review_file):
            print(f"  {RED}✗ Review file not found: {review_file}{RESET}")
            print(f"  {DIM}Make sure open_review_ui was called in the MCP server first.{RESET}")
            sys.exit(1)

        print(f"\n  {CYAN}[LOCAL]{RESET} Loading detections from file...", flush=True)
        with open(review_file) as f:
            data = json.load(f)

        repo_url = data.get("repo_url", scan_id)
        dets = []
        for d in data["detections"]:
            det = Detection(
                det_id=d["det_id"], token=d["token"],
                det_type=d["type"], line=d["line"],
                confidence=d["confidence"], file=d["file"],
                context_lines=d.get("context_lines", []),
            )
            if d.get("decision") == "approved":
                det.decision = True
            elif d.get("decision") == "rejected":
                det.decision = False
            dets.append(det)

        print(f"  {GREEN}✓ {len(dets)} detections loaded{RESET}\n")

        def save_to_file(detections):
            """Write decisions back to the review file for MCP sync_review to pick up."""
            for det in detections:
                for d in data["detections"]:
                    if d["det_id"] == det.id:
                        if det.decision is True:
                            d["decision"] = "approved"
                        elif det.decision is False:
                            d["decision"] = "rejected"
                        break
            with open(review_file, "w") as f:
                json.dump(data, f, indent=2)
            reviewed = sum(1 for det in detections if det.decision is not None)
            print(f"  {GREEN}✓ Saved {reviewed} decisions to {review_file}{RESET}")

        reviewer = HierarchicalReviewer(
            dets, repo_url, save_callback=save_to_file
        )
        reviewer.run()

    # ── submit ──────────────────────────────────────────────────────────────
    elif args.command == "submit":
        client = _get_client()
        print(f"  {DIM}Submitting {args.scan_id} for security review...{RESET}", flush=True)
        result = client.submit(args.scan_id)
        print(f"  {GREEN}✓ Submitted!{RESET}")
        print(f"  {DIM}Status:{RESET} {YELLOW}submitted{RESET} — waiting for security team approval")
        print(f"\n  {DIM}The security manager can now review this in the dashboard.{RESET}\n")

    # ── approve-all ─────────────────────────────────────────────────────────
    elif args.command == "approve-all":
        client = _get_client()
        print(f"  {DIM}Fetching detections...{RESET}", flush=True)
        data = client.get_detections(args.scan_id)
        dets = data["detections"]

        # Approve all pending
        decisions = {}
        for d in dets:
            if d["decision"] == "pending":
                decisions[d["det_id"]] = "approved"

        if decisions:
            result = client.post_review(args.scan_id, decisions)
            print(f"  {GREEN}✓ Approved {result.get('updated', 0)} detections{RESET}")
        else:
            print(f"  {DIM}All detections already reviewed{RESET}")

        # Submit for security approval
        print(f"  {DIM}Submitting for security review...{RESET}", flush=True)
        result = client.submit(args.scan_id)
        print(f"  {GREEN}✓ Submitted!{RESET}")
        print(f"  {DIM}Status:{RESET} {YELLOW}submitted{RESET} — waiting for security team")
        print(f"\n  {DIM}Next: security manager reviews in the dashboard{RESET}\n")

    # ── set-key ─────────────────────────────────────────────────────────
    elif args.command == "set-key":
        client = _get_client()
        print(f"  {DIM}Setting {args.provider} API key...{RESET}", flush=True)
        client.set_key(args.provider, args.key)
        print(f"  {GREEN}✓ {args.provider} key saved on server{RESET}")

        # Show which keys are configured
        keys = client.get_keys()
        configured = [k for k, v in keys.items() if v]
        if configured:
            print(f"  {DIM}Configured:{RESET} {', '.join(configured)}")
        print(f"\n  {DIM}Now you can use AI chat:{RESET}")
        print(f"    localmask ask <scan_id> --provider {args.provider}\n")

    # ── publish ─────────────────────────────────────────────────────────
    elif args.command == "publish":
        # Local, in-process publish (free edition, no server): scan → masked
        # git mirror the AI can read.
        if not _is_connected():
            eng = _local_engine()
            print(f"\n  {CYAN}[LOCAL]{RESET} Publishing masked copy to "
                  f"{args.target_url}...", flush=True)
            # The CLI runs per-process, so the in-memory session (masked file
            # contents) from an earlier `scan` is gone. Rebuild it from the
            # source repo, preserving token mappings, before pushing.
            from server_core import SESSIONS, _get_or_load_scan
            _sc = _get_or_load_scan(args.scan_id)
            if _sc and _sc.get("session_key") not in SESSIONS:
                eng.sync_repo(args.scan_id, auto_republish=False)
                _sc = _get_or_load_scan(args.scan_id)
            # ── Approval gate ────────────────────────────────────────────────
            # Under the default 'review' policy, the masked mirror only goes out
            # after the detections have been reviewed & approved. 'auto' skips
            # the gate (and auto-approves). --force overrides for a one-off.
            policy = _publish_policy()
            if _sc is not None and policy == "auto":
                _approve_all_local(args.scan_id)
                _sc = _get_or_load_scan(args.scan_id)
            elif _sc is not None and not getattr(args, "force", False) \
                    and not _is_approved(_sc):
                pend = _pending_count(_sc)
                print(f"  {YELLOW}⚠ Not published — this scan isn't approved "
                      f"yet.{RESET}")
                print(f"  {DIM}{pend} detection(s) still need review.{RESET} "
                      f"Approve, then publish:")
                print(f"    {CYAN}localmask review {args.scan_id}{RESET}        "
                      f"{DIM}# review each, or…{RESET}")
                print(f"    {CYAN}localmask approve-all {args.scan_id}{RESET}    "
                      f"{DIM}# approve everything{RESET}")
                print(f"  {DIM}Prefer no gate? {CYAN}localmask config "
                      f"publish-policy auto{RESET}{DIM}, or one-off "
                      f"{CYAN}--force{RESET}{DIM}.{RESET}")
                return
            # Remember the target so `sync` re-publishes on future changes.
            # Persist it — the CLI is per-process, so this must survive to disk.
            if _sc is not None:
                from server_core import _persist_scan
                _sc["publish_target"] = args.target_url
                if args.credential_id:
                    _sc["credential_id"] = args.credential_id
                _persist_scan(args.scan_id)
            # Resolve a locally-stored credential id (from `store-token`) into a
            # token, so the token never has to be passed on the command line.
            token = args.token
            if not token and args.credential_id:
                from localmask.vault_store import get_local_credential
                token = get_local_credential(args.credential_id) or ""
                if not token:
                    print(f"  {RED}✗ Unknown credential id "
                          f"'{args.credential_id}'.{RESET} Run "
                          f"`localmask store-token` to add one.")
                    return
            try:
                result = eng.publish_scan(
                    args.scan_id, args.target_url,
                    token=token, credential_id="", username=args.username)
            except Exception as e:
                _publish_error_help(str(e), args.target_url, bool(token))
                return
            print(f"  {GREEN}✓ Published masked repo{RESET}")
            print(f"  {DIM}Pushed to:{RESET}  {result.get('pushed_to', args.target_url)}")
            print(f"  {DIM}Files:{RESET}      {result.get('files', '?')}")
            _print_grant_guide(args.target_url, args.scan_id)
            return

        client = _get_client()

        # Resolve credential_id from saved config if not provided
        cred_id = args.credential_id
        token = args.token
        if not cred_id and not token:
            cred_id = _load_config().get("credential_id", "")

        # Verify scan status first
        scan = client.get_scan(args.scan_id)
        status = scan["status"]
        if status not in ("approved", "published"):
            print(f"  {YELLOW}⚠ Scan status is '{status}' — typically only approved scans are published.{RESET}")
            try:
                confirm = input(f"  {BOLD}Continue anyway? [y/N]: {RESET}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = "n"
            if confirm != "y":
                print(f"  {DIM}Aborted{RESET}\n")
                sys.exit(0)

        print(f"  {DIM}Publishing masked repo to {args.target_url}...{RESET}", flush=True)
        result = client.publish(
            args.scan_id, args.target_url,
            token=token, credential_id=cred_id,
            username=args.username,
        )
        print(f"  {GREEN}✓ Published!{RESET}")
        print(f"  {DIM}Pushed to:{RESET}  {result.get('pushed_to', args.target_url)}")
        print(f"  {DIM}Files:{RESET}      {result.get('files', '?')}")
        _print_grant_guide(args.target_url, args.scan_id)

    # ── teach (add a missed secret / ignore a false positive) ────────────
    elif args.command == "teach":
        scan_id = args.scan_id
        value = args.value
        action = "allow" if args.allow else "mask"
        if not _is_connected():
            from server_core import _get_or_load_scan
            from localmask.vault_store import get_vault_store, repo_id_for
            sc = _get_or_load_scan(scan_id)
            if not sc:
                print(f"  {RED}✗ Scan not found: {scan_id}{RESET}")
                return
            src = sc.get("repo_url", "")
            # 0) Is the value actually present in the scanned code?
            hits = _count_occurrences(src, value)
            # 1) Persist to the repo's lexicon so it applies on every scan/sync.
            store = get_vault_store(repo_id_for(src))
            store.set_lexicon(value, action=action, subtype=args.subtype)
            verb = "ignore" if action == "allow" else "mask"
            print(f"  {GREEN}✓ Taught: will always {verb} this value{RESET} "
                  f"{DIM}(repo lexicon){RESET}")
            if hits == 0:
                print(f"  {YELLOW}⚠ Not found in the scanned code{RESET} — "
                      f"double-check the value (whitespace/quotes?). Saved to the "
                      f"lexicon; it'll apply if it appears in a future scan.")
                return
            # 2) Re-scan in place so the change is visible now (tokens stay stable).
            eng = _local_engine()
            result = eng.sync_repo(scan_id, auto_republish=False)
            total = result.get("total_detections", 0)
            added = result.get("new_detections", 0)
            occ = f"{hits} occurrence" + ("s" if hits != 1 else "")
            if action == "mask" and added == 0:
                # Present in the text but the re-scan didn't add a detection.
                print(f"  {YELLOW}⚠ Found {occ} in the source, but no new "
                      f"detection was added.{RESET}")
                print(f"  {DIM}It may sit inside an already-masked secret, or be "
                      f"in a file LocalMask skips. If you just upgraded, reinstall "
                      f"to refresh (see below).{RESET}")
                return
            print(f"  {GREEN}✓ Found {occ}{RESET} — "
                  f"{added} added to the review "
                  f"({total} detections now, {CYAN}{scan_id}{RESET})")
            if action == "mask":
                print(f"  {DIM}The value is now masked as a {args.subtype} "
                      f"token; review/publish as usual.{RESET}")
            return
        client = _get_client()
        client._req("POST", f"/api/repos/{scan_id}/teach",
                    {"value": value, "action": action, "subtype": args.subtype})
        print(f"  {GREEN}✓ Taught (service).{RESET}")

    # ── sync ────────────────────────────────────────────────────────────
    elif args.command == "sync":
        scan_id = args.scan_id
        print(f"\n  {MAGENTA}[SYNC]{RESET} Re-scanning {scan_id}...", flush=True)
        print(f"  {DIM}Pulling latest code, preserving token mappings...{RESET}")

        if not _is_connected():
            eng = _local_engine()
            _tok = ""
            if args.credential_id:
                from localmask.vault_store import get_local_credential
                _tok = get_local_credential(args.credential_id) or ""
            result = eng.sync_repo(scan_id, token=_tok, auto_republish=False)
            # Re-push the masked mirror if this scan has a publish target — but
            # respect the approval gate. New/undecided detections since the last
            # approval hold the mirror until reviewed (unless policy is 'auto').
            from server_core import _get_or_load_scan
            _sc = _get_or_load_scan(scan_id)
            _target = _sc.get("publish_target", "") if _sc else ""
            policy = _publish_policy()
            _new_cnt = result.get("new_detections", 0)
            def _do_republish():
                try:
                    return eng.publish_scan(
                        scan_id, _target,
                        credential_id=_sc.get("credential_id", ""))
                except Exception as e:
                    return {"error": str(e)[:120]}
            if _target and not result.get("re_published"):
                if policy == "auto":
                    _approve_all_local(scan_id)
                    _sc = _get_or_load_scan(scan_id)
                    result["re_published"] = _do_republish()
                elif _is_approved(_sc) and _new_cnt == 0:
                    result["re_published"] = _do_republish()
                else:
                    result["held_for_review"] = True
        else:
            client = _get_client()
            cred_id = args.credential_id or _load_config().get("credential_id", "")
            body = {"credential_id": cred_id} if cred_id else {}
            result = client._req("POST", f"/api/repos/{scan_id}/sync", body)

        if result.get("error"):
            print(f"  {RED}✗ {result['error']}{RESET}\n")
        else:
            total = result.get("total_detections", 0)
            new = result.get("new_detections", 0)
            removed = result.get("removed_detections", 0)
            carried = result.get("carried_decisions", 0)
            pending = result.get("pending_review", 0)

            print(f"  {GREEN}✓ Sync complete{RESET}\n")
            print(f"  {BOLD}Scan ID:{RESET}     {CYAN}{scan_id}{RESET}")
            print(f"  {DIM}Total:{RESET}       {total} detections")
            # Newly-detected secrets since the last scan — shown prominently.
            if new > 0:
                print(f"  {BG_YELLOW}{BOLD} NEW {RESET} "
                      f"{BOLD}{YELLOW}{new} new secret(s) detected since last "
                      f"sync{RESET}")
            else:
                print(f"  {DIM}New:{RESET}         0 new detections")
            if removed > 0:
                print(f"  {DIM}Removed:{RESET}     {removed} (no longer in code)")
            print(f"  {DIM}Carried:{RESET}     {carried} previous decisions preserved")
            if pending > 0:
                print(f"  {YELLOW}Pending:{RESET}     {pending} need review")

            if result.get("re_published"):
                pub = result["re_published"]
                if pub.get("ok"):
                    print(f"\n  {GREEN}✓ Masked repo auto-republished to {pub.get('pushed_to', '?')}{RESET}")
                else:
                    print(f"\n  {YELLOW}⚠ Auto-republish failed:{RESET} "
                          f"{pub.get('error', 'unknown')}")
            elif result.get("held_for_review"):
                print(f"\n  {YELLOW}⚠ Masked mirror NOT updated — "
                      f"held for review.{RESET}")
                print(f"  {DIM}{new} new + {pending} pending detection(s) must be "
                      f"approved before the mirror is republished.{RESET}")
                print(f"    {CYAN}localmask review {scan_id}{RESET}  or  "
                      f"{CYAN}localmask approve-all {scan_id}{RESET}  then  "
                      f"{CYAN}localmask publish {scan_id} <url>{RESET}")
                print(f"  {DIM}(auto-publish on every change: "
                      f"{CYAN}localmask config publish-policy auto{RESET}{DIM}){RESET}")

            if new > 0 and not result.get("held_for_review"):
                print(f"\n  {DIM}Next: review new detections:{RESET}")
                print(f"    localmask review {scan_id}")
            print()

    # ── hook ────────────────────────────────────────────────────────────
    elif args.command == "hook":
        import stat as stat_mod
        repo_path = os.path.abspath(args.repo)
        scan_id = args.scan_id
        hook_type = args.type

        hooks_dir = os.path.join(repo_path, ".git", "hooks")
        if not os.path.isdir(hooks_dir):
            print(f"  {RED}✗ Not a git repo: {repo_path}{RESET}\n")
            sys.exit(1)

        hook_path = os.path.join(hooks_dir, hook_type)
        localmask_bin = os.path.expanduser("~/.localmask/localmask")

        hook_script = f"""#!/bin/bash
# LocalMask Pro — auto-sync masked repo on {hook_type}
# Scan ID: {scan_id}

echo "🔐 LocalMask: syncing masked repo..."
if command -v localmask &>/dev/null; then
    localmask sync {scan_id} 2>&1 | tail -5
elif [ -f "{localmask_bin}" ]; then
    "{localmask_bin}" sync {scan_id} 2>&1 | tail -5
else
    echo "⚠ LocalMask not found — skipping sync"
fi
"""

        if os.path.exists(hook_path):
            with open(hook_path) as f:
                existing = f.read()
            if "LocalMask" in existing:
                print(f"  {GREEN}✓ Hook already installed in {hook_type}{RESET}\n")
                sys.exit(0)
            with open(hook_path, "a") as f:
                f.write("\n" + hook_script)
        else:
            with open(hook_path, "w") as f:
                f.write(hook_script)

        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat_mod.S_IEXEC | stat_mod.S_IXGRP | stat_mod.S_IXOTH)

        print(f"\n  {GREEN}✓ Git {hook_type} hook installed!{RESET}")
        print(f"  {DIM}Repo:{RESET}    {repo_path}")
        print(f"  {DIM}Scan ID:{RESET} {scan_id}")
        print(f"  {DIM}Hook:{RESET}    {hook_path}")
        print(f"\n  Every {hook_type.replace('-', ' ')} will auto-sync the masked repo.")
        print(f"  {DIM}Token mappings are preserved — only new secrets need review.{RESET}\n")

    # ── activate ────────────────────────────────────────────────────────
    elif args.command == "activate":
        # License activation is local — no server needed
        sys.path.insert(0, os.path.dirname(__file__))
        try:
            from licensing import LicenseManager
            mgr = LicenseManager()
            result = mgr.activate(args.license_key)
            if result.get("ok"):
                print(f"  {GREEN}✓ License activated!{RESET}")
                print(f"  {DIM}Tier:{RESET}       {BOLD}{result['tier_name']}{RESET}")
                print(f"  {DIM}Activated:{RESET}  {result['activated_at'][:19]}")
                print(f"\n  {DIM}You now have full access to LocalMask Pro.{RESET}\n")
            else:
                print(f"  {RED}✗ Activation failed: {result.get('error', 'unknown')}{RESET}\n")
        except ImportError:
            print(f"  {RED}✗ licensing.py not found. Ensure you're in the LocalMask directory.{RESET}\n")

    # ── license ─────────────────────────────────────────────────────────
    elif args.command == "license":
        sys.path.insert(0, os.path.dirname(__file__))
        try:
            from licensing import LicenseManager
            mgr = LicenseManager()
            status = mgr.get_status()
            print(f"\n{BOLD}{'═' * 50}{RESET}")
            print(f"{BOLD}  LocalMask Pro — License{RESET}")
            print(f"{BOLD}{'═' * 50}{RESET}")
            tier_color = GREEN if status["tier"] != "free" else DIM
            print(f"  {DIM}Tier:{RESET}       {tier_color}{BOLD}{status['tier_name']}{RESET}")
            print(f"  {DIM}License:{RESET}    {status['license_key']}")
            if status.get("activated_at"):
                print(f"  {DIM}Activated:{RESET}  {status['activated_at'][:19]}")
            print(f"  {DIM}Custom rules:{RESET} {'Yes' if status['custom_rules'] else 'No'}")
            print(f"\n  {BOLD}Usage Today:{RESET}")
            for action, info in status.get("usage_today", {}).items():
                limit_str = str(info['limit']) if info['limit'] != 'unlimited' else '∞'
                used = info['used']
                bar_len = 20
                if info['limit'] != 'unlimited' and info['limit'] > 0:
                    filled = min(bar_len, int(used / info['limit'] * bar_len))
                    bar = f"{YELLOW}{'█' * filled}{'░' * (bar_len - filled)}{RESET}"
                else:
                    bar = f"{GREEN}∞{RESET}"
                print(f"    {action:<8} {used:>3}/{limit_str:<10} {bar}")
            print(f"\n{'═' * 50}\n")
        except ImportError:
            print(f"  {RED}✗ licensing.py not found.{RESET}\n")

    # ── ask ──────────────────────────────────────────────────────────────
    elif args.command == "ask":
        client = _get_client()
        scan_id = args.scan_id

        # Verify scan exists
        scan = client.get_scan(scan_id)
        src_label = "published git repo" if args.source == "git" else "platform memory"
        print(f"\n  {MAGENTA}[AI]{RESET} Scan: {CYAN}{scan_id}{RESET}  "
              f"Status: {BOLD}{scan['status']}{RESET}  "
              f"Repo: {scan['repo_url']}")
        print(f"  {DIM}Source: {src_label}  — AI only sees masked content.{RESET}\n")

        if args.question:
            # Single question mode
            print(f"  {DIM}Asking...{RESET}", flush=True)
            r = client.ask(scan_id, args.question, args.provider, args.model,
                          args.source, args.git_url)
            if r.get("error"):
                print(f"  {RED}Error: {r['error']}{RESET}")
            else:
                print(f"  {DIM}Provider:{RESET} {r.get('provider', '?')}  "
                      f"{DIM}Turn:{RESET} {r.get('turns', 1)}")
                if r.get("masked_question") != args.question:
                    print(f"  {DIM}Sent masked:{RESET} {r['masked_question']}")
                print(f"\n{r.get('answer', '')}\n")
        else:
            # Interactive mode
            print(f"  {DIM}Interactive mode — type your questions. "
                  f"Commands: /reset /quit{RESET}\n")
            turn = 0
            while True:
                try:
                    q = input(f"  {BOLD}You → {RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n  {DIM}Bye{RESET}\n")
                    break

                if not q:
                    continue
                if q.lower() in ("/quit", "/exit", "/q"):
                    print(f"  {DIM}Bye{RESET}\n")
                    break
                if q.lower() == "/reset":
                    client.ask_reset(scan_id)
                    turn = 0
                    print(f"  {GREEN}✓ Chat reset{RESET}\n")
                    continue

                print(f"  {DIM}Thinking...{RESET}", flush=True)
                r = client.ask(scan_id, q, args.provider, args.model,
                              args.source, args.git_url)
                if r.get("error"):
                    print(f"  {RED}Error: {r['error']}{RESET}\n")
                    continue

                turn = r.get("turns", turn + 1)
                answer = r.get("answer", "")
                print(f"\n  {CYAN}AI ({r.get('provider','?')} · turn {turn}):{RESET}")
                # Indent the answer
                for line in answer.split("\n"):
                    print(f"  {line}")
                print()


if __name__ == "__main__":
    main()
