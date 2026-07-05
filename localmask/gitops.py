"""Secure git operations (GIT_ASKPASS) and publish filters."""
import os
import re
import shutil
import stat
import subprocess
import tempfile


# ── URL validation ──────────────────────────────────────────────────────────
# Git URLs are attacker-influenced input (API / MCP callers). Two attack
# classes are blocked here:
#   1. Argument injection — a "URL" starting with "-" becomes a git option
#      (e.g. --upload-pack=<cmd> executes commands on clone).
#   2. Transport tricks — ext:: URLs execute arbitrary commands.
_ALLOWED_URL_RES = [
    re.compile(r"^https?://[\w.-]+(?::\d+)?/\S+$"),      # https://host/path
    re.compile(r"^ssh://[\w.@-]+(?::\d+)?/\S+$"),        # ssh://user@host/path
    re.compile(r"^git@[\w.-]+:[\w./~-]+$"),              # git@host:org/repo
    re.compile(r"^file:///\S+$"),                        # file:///abs/path
]


def _validate_git_url(url: str) -> str:
    """Return the URL if it is a safe git remote; raise ValueError otherwise.
    Local directory paths are allowed when they exist on disk."""
    url = (url or "").strip()
    if not url or url.startswith("-"):
        raise ValueError(f"Invalid git URL: {url!r}")
    for rx in _ALLOWED_URL_RES:
        if rx.match(url):
            return url
    # Local path remote (used by tests and on-disk bare repos)
    if not url.startswith("-") and os.path.exists(url):
        return url
    raise ValueError(
        f"Unsupported git URL (allowed: https, ssh, git@, file://, "
        f"existing local path): {url!r}")


# ── Secure Git Operations ──────────────────────────────────────────────────
# Use GIT_ASKPASS so tokens never appear in process args, URLs, or .git/config

def _git_clone_secure(repo_url: str, dest_dir: str, token: str = ""):
    """Clone a repo using GIT_ASKPASS — token never in URL or process args."""
    repo_url = _validate_git_url(repo_url)
    env = os.environ.copy()

    if token:
        # Create a temporary askpass script that responds to git's prompts:
        # "Username for ..." → x-access-token
        # "Password for ..." → the actual token
        askpass_fd, askpass_path = tempfile.mkstemp(prefix="lm_askpass_", suffix=".sh")
        try:
            with os.fdopen(askpass_fd, "w") as f:
                f.write('#!/bin/sh\n'
                        'case "$1" in\n'
                        '  Username*) echo "x-access-token" ;;\n'
                        '  Password*) echo "$GIT_TOKEN" ;;\n'
                        '  *) echo "$GIT_TOKEN" ;;\n'
                        'esac\n')
            os.chmod(askpass_path, stat.S_IRWXU)  # 0o700
            env["GIT_ASKPASS"] = askpass_path
            env["GIT_TOKEN"] = token
            env["GIT_TERMINAL_PROMPT"] = "0"
            # Disable any OS credential helpers (e.g. macOS Keychain) so
            # GIT_ASKPASS is actually consulted
            env["GIT_CONFIG_NOSYSTEM"] = "1"

            subprocess.run(
                ["git", "-c", "credential.helper=", "clone",
                 "--depth", "1", "-q", "--", repo_url, dest_dir],
                check=True, timeout=120, capture_output=True, env=env,
            )
        finally:
            os.unlink(askpass_path)
            env.pop("GIT_TOKEN", None)
    else:
        subprocess.run(
            ["git", "clone", "--depth", "1", "-q", "--", repo_url, dest_dir],
            check=True, timeout=120, capture_output=True, env=env,
        )


def _git_push_secure(repo_dir: str, remote_url: str, token: str = "",
                     username: str = ""):
    """Push to remote using GIT_ASKPASS — token never in URL or process args."""
    import logging
    logger = logging.getLogger("localmask.git")
    logger.info(f"_git_push_secure: token={'YES(len=' + str(len(token)) + ')' if token else 'EMPTY'}, username={username!r}")
    remote_url = _validate_git_url(remote_url)
    env = os.environ.copy()

    askpass_path = None
    git_cfg_dir = None
    if token:
        askpass_fd, askpass_path = tempfile.mkstemp(prefix="lm_askpass_", suffix=".sh")
        with os.fdopen(askpass_fd, "w") as f:
            # Respond with username or token based on git's prompt.
            # Both come from env vars — never interpolated into the script,
            # so a hostile username can't inject shell commands.
            f.write('#!/bin/sh\n'
                    'case "$1" in\n'
                    '  Username*) echo "${GIT_USERNAME:-x-access-token}" ;;\n'
                    '  Password*) echo "$GIT_TOKEN" ;;\n'
                    '  *) echo "$GIT_TOKEN" ;;\n'
                    'esac\n')
        os.chmod(askpass_path, stat.S_IRWXU)
        env["GIT_ASKPASS"] = askpass_path
        env["GIT_TOKEN"] = token
        if username:
            env["GIT_USERNAME"] = username
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        # Create an empty gitconfig to prevent macOS Keychain/osxkeychain
        # credential helper from overriding our GIT_ASKPASS token
        git_cfg_dir = tempfile.mkdtemp(prefix="lm_gitcfg_")
        empty_cfg = os.path.join(git_cfg_dir, ".gitconfig")
        open(empty_cfg, "w").write("[credential]\n\thelper =\n")
        env["HOME"] = git_cfg_dir
        env["XDG_CONFIG_HOME"] = git_cfg_dir

    try:
        run = lambda *a: subprocess.run(
            a, cwd=repo_dir, check=True, timeout=120, capture_output=True, env=env)
        run("git", "init", "-q")
        run("git", "add", "-A")
        run("git", "-c", "user.email=ide@localmask", "-c", "user.name=LocalMask",
            "commit", "-q", "-m", "LocalMask: masked repository")
        run("git", "remote", "add", "origin", remote_url)
        run("git", "push", "-q", "-u", "origin", "HEAD:main", "--force")
    finally:
        if askpass_path and os.path.exists(askpass_path):
            os.unlink(askpass_path)
        if git_cfg_dir and os.path.exists(git_cfg_dir):
            shutil.rmtree(git_cfg_dir, ignore_errors=True)
        env.pop("GIT_TOKEN", None)
        env.pop("GIT_USERNAME", None)


# Tool config files — scan them (to detect secrets) but exclude from publish.
# These are IDE/tool integration files that should stay local.
PUBLISH_EXCLUDE_FILES = {
    ".mcp.json", "CLAUDE.md", "localmask.sh",
}

PUBLISH_EXCLUDE_PREFIXES = (
    ".vscode/",
    ".github/copilot",
)


def _should_publish(rel: str) -> bool:
    """Return True if this file should be included in the published masked repo."""
    rel_norm = rel.replace("\\", "/")
    if rel_norm in PUBLISH_EXCLUDE_FILES:
        return False
    for prefix in PUBLISH_EXCLUDE_PREFIXES:
        if rel_norm.startswith(prefix):
            return False
    return True


def parse_git_target(url: str):
    """(host, owner, repo) for a github/gitlab-style URL, else None."""
    u = (url or "").strip()
    m = re.match(r"git@([\w.-]+):([^/]+)/(.+?)(?:\.git)?/?$", u)
    if not m:
        m = re.match(r"(?:ssh://git@|https?://)([\w.-]+)/([^/]+)/(.+?)(?:\.git)?/?$", u)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def _gh_cli_available() -> bool:
    return shutil.which("gh") is not None


def remote_repo_exists(url: str, token: str = "") -> bool | None:
    """True/False if we can tell whether the remote repo exists, else None.
    Uses the GitHub API with a token, or the `gh` CLI (its own auth)."""
    tgt = parse_git_target(url)
    if not tgt:
        return None
    host, owner, repo = tgt
    if host == "github.com" and token:
        import urllib.request, urllib.error
        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "localmask"})
        try:
            urllib.request.urlopen(req, timeout=20)
            return True
        except urllib.error.HTTPError as e:
            return False if e.code == 404 else None
        except Exception:
            return None
    if host == "github.com" and _gh_cli_available():
        r = subprocess.run(["gh", "repo", "view", f"{owner}/{repo}"],
                           capture_output=True, timeout=30)
        return r.returncode == 0
    return None


def create_remote_repo(url: str, token: str = "", private: bool = True):
    """Create the remote masked repo. Returns (ok, message). Supports GitHub via
    the API (with a token) or the `gh` CLI (its own auth)."""
    tgt = parse_git_target(url)
    if not tgt:
        return False, "unrecognized git URL — create the repo manually."
    host, owner, repo = tgt
    if host != "github.com":
        return False, (f"auto-create supports GitHub; create {owner}/{repo} on "
                       f"{host} manually, then re-run.")
    desc = "LocalMask masked mirror — tokens only, no real secrets."
    if token:
        import urllib.request, urllib.error, json as _json
        # user vs org namespace
        otype = "User"
        try:
            ir = urllib.request.Request(
                f"https://api.github.com/users/{owner}",
                headers={"Authorization": f"Bearer {token}",
                         "User-Agent": "localmask"})
            with urllib.request.urlopen(ir, timeout=20) as resp:
                otype = _json.loads(resp.read()).get("type", "User")
        except Exception:
            pass
        path = (f"/orgs/{owner}/repos" if otype == "Organization"
                else "/user/repos")
        body = _json.dumps({"name": repo, "private": private,
                            "description": desc}).encode()
        req = urllib.request.Request(
            "https://api.github.com" + path, data=body, method="POST",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json",
                     "User-Agent": "localmask"})
        try:
            urllib.request.urlopen(req, timeout=30)
            return True, ""
        except Exception as e:
            detail = ""
            if hasattr(e, "read"):
                try:
                    detail = e.read().decode()[:200]
                except Exception:
                    pass
            return False, f"GitHub API create failed: {getattr(e,'code','')} {detail or e}"
    if _gh_cli_available():
        vis = "--private" if private else "--public"
        r = subprocess.run(
            ["gh", "repo", "create", f"{owner}/{repo}", vis, "--description", desc],
            capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            return True, ""
        return False, f"gh repo create failed: {r.stderr.strip()[:200]}"
    return False, ("no token and `gh` not found — run `localmask store-token`, "
                   "or `gh auth login`, or create the repo manually.")


def _git_tracked_files(src_dir: str) -> list[str] | None:
    """Return list of git-tracked relative paths, or None if not a git repo."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=src_dir, capture_output=True, timeout=30, text=True)
        if result.returncode == 0:
            return [f for f in result.stdout.strip().split("\n") if f]
    except Exception:
        pass
    return None


