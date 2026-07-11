"""Git-history scanning: secrets committed then removed still live in the git
log and are invisible to a working-tree scan. scan_history() must surface the
removed ones and NOT re-report secrets that still exist at HEAD."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LOCALMASK_EDITION", "free")
os.environ.setdefault("OLLAMA_HOST", "http://127.0.0.1:1")

from server_core import LocalMaskEngine  # noqa: E402


def _git(d, *args):
    subprocess.run(["git", "-C", d, *args], check=True,
                   capture_output=True)


# Assemble the fake test tokens from fragments so no literal secret sits in the
# source (keeps GitHub push-protection / our own scanners happy — these are all
# canonical fake examples, but a public repo shouldn't carry secret-shaped
# literals).
STRIPE = "sk_" + "live_" + "51H8xR2eZvKYlo2Cq9Wc3nT7pXbF4mD8"
AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"
GH = "ghp_" + "1234567890abcdefghijklmnopqrstuvwx99"


def _make_repo(tmp):
    d = os.path.join(tmp, "repo")
    os.makedirs(d, exist_ok=True)
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@t.co")
    _git(d, "config", "user.name", "t")
    cfg = os.path.join(d, "config.py")
    # commit 1: two secrets
    with open(cfg, "w") as f:
        f.write(f'STRIPE = "{STRIPE}"\nAWS = "{AWS}"\n')
    _git(d, "add", "-A"); _git(d, "commit", "-qm", "secrets")
    # commit 2: remove them
    with open(cfg, "w") as f:
        f.write('STRIPE = os.environ["STRIPE"]\n')
    _git(d, "add", "-A"); _git(d, "commit", "-qm", "remove")
    # commit 3: a NEW secret that stays in the tree
    with open(cfg, "a") as f:
        f.write(f'GH = "{GH}"\n')
    _git(d, "add", "-A"); _git(d, "commit", "-qm", "current")
    return d


def test_history_surfaces_removed_secrets(tmp_path):
    d = _make_repo(str(tmp_path))
    hits = LocalMaskEngine().scan_history(d)
    values = {h["value"] for h in hits}
    # The two removed secrets are found...
    assert STRIPE in values
    assert AWS in values
    # ...and correctly typed (not "None").
    by_val = {h["value"]: h["type"] for h in hits}
    assert by_val[AWS] == "aws_access_key_id"
    assert "stripe" in by_val[STRIPE].lower()


def test_history_excludes_current_tree_secret(tmp_path):
    d = _make_repo(str(tmp_path))
    hits = LocalMaskEngine().scan_history(d)
    values = {h["value"] for h in hits}
    # The still-present ghp_ secret must NOT appear as "removed".
    assert GH not in values


def test_history_noop_on_non_git_dir(tmp_path):
    plain = os.path.join(str(tmp_path), "plain")
    os.makedirs(plain)
    assert LocalMaskEngine().scan_history(plain) == []
