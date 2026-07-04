"""Auto-publish helper — composes state + vault + gitops.

Kept in its own module (rather than gitops.py) so the lower-level modules
stay leaf nodes with no back-edges into state/vault.
"""
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from .state import SESSIONS, _notify
from .vault import _resolve_credential
from .gitops import _should_publish, _git_push_secure


def _auto_publish(scan: dict) -> dict | None:
    """Auto-publish masked repo after approval if scan has a publish target configured."""
    session = SESSIONS.get(scan.get("session_key", ""))
    if not session:
        return None

    target_url = scan.get("publish_target", "")
    credential_id = scan.get("credential_id", "")
    if not target_url or not credential_id:
        return None

    token = _resolve_credential(credential_id)
    if not token:
        return None

    tmp = tempfile.mkdtemp(prefix="lm_autopub_")
    try:
        written = 0
        for rel, d in session["files"].items():
            if not _should_publish(rel):
                continue
            out = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(out) or tmp, exist_ok=True)
            open(out, "w").write(d["masked"])
            written += 1

        username = scan.get("username", "")
        _git_push_secure(tmp, target_url, token, username)

        scan["status"] = "published"
        scan["updated_at"] = datetime.now(timezone.utc).isoformat()

        _notify(scan["scan_id"], scan.get("submitted_by", "developer"), "published",
                f"Masked repository published to {target_url}. "
                f"{written} files pushed. You can now access the masked repo.")

        return {"pushed_to": target_url, "files": written}
    except subprocess.CalledProcessError:
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
