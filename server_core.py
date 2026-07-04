"""
LocalMask Pro — Core Engine (shared between FastAPI server & MCP server).

This module wraps the existing server.py functions/globals into a clean
LocalMaskEngine class so both the HTTP API and the MCP server can use
the same scanning, review, and publishing logic without duplication.
"""
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone

# Import the engine directly from the localmask package — NOT from server.py.
# This keeps the MCP/CLI path independent of the web layer, so the free
# edition can ship without server.py / ui.html.
from regex_rules_safe import RegexRulesSafe
from localmask.state import (
    SESSIONS, SCANS, KEYS, APP_CONFIG, NOTIFICATIONS,
    _new_session, _summary, _gen_scan_id, _flatten_detections,
    _scan_stats, _scan_to_dict, _notify,
    _persist_scan, _get_or_load_scan,
)
from localmask.vault import (
    CREDENTIALS, CRED_TTL_SECONDS,
    _resolve_credential, _vault_encrypt, _vault_decrypt, _cred_cleanup,
)
from localmask.gitops import _git_clone_secure, _git_push_secure, _should_publish
from localmask.masking import _mask_text, _rehydrate
from localmask.engine import _scan_dir, _scan_file, _remask, _get_bert, _get_ner
from localmask.publish import _auto_publish

# Ask-AI (cloud egress — the only non-local feature). Optional: absent in the
# free edition, so import defensively.
try:
    from localmask.askai import (
        _call_model, _build_repo_context, _load_repo_text_from_git,
        SYSTEM_PROMPT,
    )
    _ASKAI_AVAILABLE = True
except ImportError:
    _ASKAI_AVAILABLE = False
    SYSTEM_PROMPT = ""

    def _call_model(*a, **k):
        raise RuntimeError("Ask-AI is a Pro feature — not available in this edition.")

    def _build_repo_context(*a, **k):
        raise RuntimeError("Ask-AI is a Pro feature — not available in this edition.")

    def _load_repo_text_from_git(*a, **k):
        raise RuntimeError("Ask-AI is a Pro feature — not available in this edition.")


class LocalMaskEngine:
    """Unified engine for LocalMask Pro operations.

    Wraps the existing server.py logic into a class interface that
    both the FastAPI routes and MCP tools can call.

    State is shared via server.py module-level globals (SESSIONS, SCANS, etc.)
    so the FastAPI server and this engine see the same data.
    """

    def __init__(self):
        # Force lazy-load of classifiers on first use
        self._bert_loaded = False
        self._ner_loaded = False

    def _ensure_classifiers(self):
        if not self._bert_loaded:
            _get_bert()
            self._bert_loaded = True
        if not self._ner_loaded:
            _get_ner()
            self._ner_loaded = True

    # ── Scanning ─────────────────────────────────────────────────────────────

    def scan_repo(self, source: str, sensitivity: str = "standard",
                  org: str = "default", credential_id: str = "",
                  token: str = "", submitted_by: str = "developer") -> dict:
        """Scan a repo (URL or local path). Returns scan record dict."""
        self._ensure_classifiers()

        if sensitivity not in ("minimal", "standard", "strict"):
            sensitivity = "standard"

        # Resolve credential
        resolved_token = ""
        if credential_id:
            resolved_token = _resolve_credential(credential_id)
        elif token:
            resolved_token = token

        # Clone or resolve local path
        is_url = source.startswith(("http://", "https://", "git@"))
        if is_url:
            src_dir = tempfile.mkdtemp(prefix="lm_repo_")
            try:
                _git_clone_secure(source, src_dir, resolved_token)
            except subprocess.CalledProcessError as e:
                shutil.rmtree(src_dir, ignore_errors=True)
                raise RuntimeError(f"Clone failed: {e.stderr.decode()[:300]}")
        else:
            src_dir = source if os.path.isabs(source) else os.path.join(os.getcwd(), source)
            if not os.path.isdir(src_dir):
                raise FileNotFoundError(f"Not found: {src_dir}")

        # Create session and scan
        scan_id = _gen_scan_id()
        session_key = f"{org}_{scan_id}"
        session = _new_session(src_dir, is_url)
        session["sensitivity"] = sensitivity
        _scan_dir(session, src_dir)
        SESSIONS[session_key] = session

        # Build scan record
        detections = _flatten_detections(session)
        now = datetime.now(timezone.utc).isoformat()

        scan_record = {
            "scan_id": scan_id,
            "repo_url": source,
            "org": org,
            "status": "draft",
            "created_at": now,
            "updated_at": now,
            "submitted_by": submitted_by,
            "reviewed_by": None,
            "review_comment": None,
            "session_key": session_key,
            "credential_id": credential_id,
            "publish_target": "",
            "username": "",
            "detections": detections,
            "summary_stats": _scan_stats(detections, session),
        }
        SCANS[scan_id] = scan_record
        _persist_scan(scan_id)
        return _scan_to_dict(scan_record)

    # ── Sync (re-scan on git update) ───────────────────────────────────────

    def sync_repo(self, scan_id: str, credential_id: str = "",
                  token: str = "") -> dict:
        """Re-scan a previously scanned repo, preserve existing token mappings,
        detect new secrets, and optionally re-publish the masked repo.

        This is the core of the git integration: source repo changes →
        re-scan → reuse token vault → flag new detections → update masked remote.
        """
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")

        old_session = SESSIONS.get(scan.get("session_key", ""))
        source = scan["repo_url"]
        org = scan["org"]
        sensitivity = scan.get("summary_stats", {}).get("sensitivity", "standard")
        if old_session:
            sensitivity = old_session.get("sensitivity", sensitivity)

        self._ensure_classifiers()

        # Resolve credential
        resolved_token = ""
        if credential_id:
            resolved_token = _resolve_credential(credential_id)
        elif token:
            resolved_token = token
        elif scan.get("credential_id"):
            try:
                resolved_token = _resolve_credential(scan["credential_id"])
            except Exception:
                pass

        # Clone fresh copy
        is_url = source.startswith(("http://", "https://", "git@"))
        if is_url:
            src_dir = tempfile.mkdtemp(prefix="lm_sync_")
            try:
                _git_clone_secure(source, src_dir, resolved_token)
            except subprocess.CalledProcessError as e:
                shutil.rmtree(src_dir, ignore_errors=True)
                raise RuntimeError(f"Clone failed: {e.stderr.decode()[:300]}")
        else:
            src_dir = source if os.path.isabs(source) else os.path.join(os.getcwd(), source)
            if not os.path.isdir(src_dir):
                raise FileNotFoundError(f"Not found: {src_dir}")

        # Create new session but carry over the token vault from old session
        new_session = _new_session(src_dir, is_url)
        new_session["sensitivity"] = sensitivity

        # Preserve existing token mappings (vault + rev_vault + taught + allowed)
        # tok_count MUST carry over too: it's the per-type counter used to mint
        # new token names. Without it, a newly-detected secret of an existing
        # type restarts at _0 and collides with a carried-over token
        # (e.g. two distinct values both mapped to ~[AWS_ACCESS_KEY_ID_0]~),
        # corrupting rehydration.
        if old_session:
            new_session["vault"] = dict(old_session.get("vault", {}))
            new_session["rev_vault"] = dict(old_session.get("rev_vault", {}))
            new_session["taught"] = dict(old_session.get("taught", {}))
            new_session["allowed"] = set(old_session.get("allowed", set()))
            new_session["tok_count"] = dict(old_session.get("tok_count", {}))

        # Re-scan with preserved vault
        _scan_dir(new_session, src_dir)

        # Swap session
        session_key = scan["session_key"]
        SESSIONS[session_key] = new_session

        # Diff detections
        old_dets = {d["det_id"]: d for d in scan.get("detections", [])}
        new_dets = _flatten_detections(new_session)

        # Carry over review decisions for detections that still exist
        # Match by (file, line, type) since det_ids may change
        old_by_loc = {}
        for d in old_dets.values():
            loc_key = (d["file"], d.get("type", ""), d.get("value", ""))
            old_by_loc[loc_key] = d

        carried = 0
        new_count = 0
        removed_count = len(old_dets)
        new_loc_keys = set()

        for d in new_dets:
            loc_key = (d["file"], d.get("type", ""), d.get("value", ""))
            new_loc_keys.add(loc_key)
            old_d = old_by_loc.get(loc_key)
            if old_d:
                # Carry over decision
                if old_d.get("decision") in ("approved", "rejected"):
                    d["decision"] = old_d["decision"]
                    carried += 1
                removed_count -= 1
            else:
                new_count += 1

        now = datetime.now(timezone.utc).isoformat()
        scan["detections"] = new_dets
        scan["summary_stats"] = _scan_stats(new_dets, new_session)
        scan["updated_at"] = now
        scan["last_synced"] = now

        # If scan was published, keep it approved so it can be re-published
        if scan["status"] == "published":
            scan["status"] = "approved"

        # Auto re-publish if target is set and scan is approved
        pub_result = None
        if scan["status"] == "approved" and scan.get("publish_target"):
            try:
                pub_result = self.publish_scan(
                    scan_id, scan["publish_target"],
                    credential_id=scan.get("credential_id", ""),
                    username=scan.get("username", ""),
                )
            except Exception:
                pub_result = {"error": "Auto re-publish failed"}

        result = {
            "ok": True,
            "scan_id": scan_id,
            "total_detections": len(new_dets),
            "new_detections": new_count,
            "removed_detections": removed_count,
            "carried_decisions": carried,
            "pending_review": len([d for d in new_dets if d.get("decision", "pending") == "pending"]),
            "synced_at": now,
        }
        if pub_result:
            result["re_published"] = pub_result
        return result

    # ── Scan Queries ─────────────────────────────────────────────────────────

    def list_scans(self, org: str = "") -> list:
        """List all scans, optionally filtered by org."""
        repos = []
        for scan in sorted(SCANS.values(), key=lambda s: s["created_at"], reverse=True):
            if org and scan["org"] != org:
                continue
            repos.append(_scan_to_dict(scan))
        return repos

    def get_scan(self, scan_id: str) -> dict:
        """Get scan summary."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        return _scan_to_dict(scan)

    def get_detections(self, scan_id: str) -> dict:
        """Get detection metadata (no real values exposed)."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "repo_url": scan["repo_url"],
            "detections": scan["detections"],
            "summary_stats": scan["summary_stats"],
        }

    def get_file_masked(self, scan_id: str, path: str) -> dict:
        """Get masked file content."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        session = SESSIONS.get(scan.get("session_key", ""))
        if not session:
            raise RuntimeError("Session expired")
        fd = session["files"].get(path)
        if not fd:
            raise FileNotFoundError(f"File not found: {path}")
        return {
            "path": path,
            "masked_content": fd["masked"],
            "detections": [d for d in scan["detections"] if d["file"] == path],
        }

    def get_file_list(self, scan_id: str) -> list:
        """Get list of files with detection counts."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        session = SESSIONS.get(scan.get("session_key", ""))
        if not session:
            raise RuntimeError("Session expired")
        det_by_file: dict = {}
        for d in scan["detections"]:
            det_by_file.setdefault(d["file"], []).append(d)
        return [
            {"path": rel, "detection_count": len(det_by_file.get(rel, []))}
            for rel in sorted(session["files"])
        ]

    # ── Review & Workflow ────────────────────────────────────────────────────

    def review_detections(self, scan_id: str, decisions: dict,
                          reviewer: str = "developer") -> dict:
        """Submit detection-level decisions. decisions = {det_id: 'approved'|'rejected'}"""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")

        updated = 0
        feedback_added = 0
        bert = _get_bert()

        for det in scan["detections"]:
            if det["det_id"] in decisions:
                decision = decisions[det["det_id"]]
                if decision in ("approved", "rejected"):
                    det["decision"] = decision
                    updated += 1
                    if bert:
                        label = 1 if decision == "approved" else 0
                        entity = det.get("value", det.get("token", ""))
                        context = ""
                        ctx_lines = det.get("context_lines", [])
                        if ctx_lines:
                            context = " ".join(
                                cl.get("text", "") for cl in ctx_lines
                            )[:200]
                        file_type = det.get("file", "").rsplit(".", 1)[-1] if det.get("file") else "txt"
                        ner_lbl = ""
                        src = det.get("source", "")
                        if "ner" in src:
                            ner_lbl = det.get("type", "").replace("ner_", "").upper()
                        bert.add_feedback(entity, context, file_type, label,
                                          source="reviewer", ner_label=ner_lbl)
                        feedback_added += 1

        scan["updated_at"] = datetime.now(timezone.utc).isoformat()
        _persist_scan(scan_id)
        return {"ok": True, "updated": updated, "scan_id": scan_id,
                "feedback_added": feedback_added}

    def submit_scan(self, scan_id: str, submitted_by: str = "developer") -> dict:
        """Submit scan for security review."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        if scan["status"] not in ("draft", "rejected"):
            raise ValueError(f"Cannot submit from status '{scan['status']}'")

        scan["submitted_by"] = submitted_by
        scan["status"] = "submitted"
        scan["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Auto-approval check
        if APP_CONFIG.get("auto_approve_enabled"):
            threshold = APP_CONFIG.get("auto_approve_threshold", 0.95)
            dets = scan.get("detections", [])
            if dets and all(d.get("confidence", 0) >= threshold for d in dets):
                scan["status"] = "approved"
                scan["reviewed_by"] = "auto_approve"
                scan["review_comment"] = (
                    f"Auto-approved: all {len(dets)} detections above "
                    f"{threshold*100:.0f}% confidence threshold"
                )
                _auto_publish(scan)
                return {"ok": True, "status": "approved", "scan_id": scan_id,
                        "auto_approved": True}

        _notify(scan_id, "security_team", "submitted",
                f"Scan {scan_id} submitted by {submitted_by}")
        return {"ok": True, "status": "submitted", "scan_id": scan_id}

    def approve_scan(self, scan_id: str, reviewer: str = "security_manager",
                     comment: str = "") -> dict:
        """Security manager approves the scan."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        if scan["status"] not in ("submitted", "under_review"):
            raise ValueError(f"Cannot approve from status '{scan['status']}'")

        scan["status"] = "approved"
        scan["reviewed_by"] = reviewer
        scan["review_comment"] = comment
        scan["updated_at"] = datetime.now(timezone.utc).isoformat()

        _notify(scan_id, scan.get("submitted_by", "developer"), "approved",
                f"Scan {scan_id} approved by {reviewer}")
        pub_result = _auto_publish(scan)
        result = {"ok": True, "status": "approved", "scan_id": scan_id}
        if pub_result:
            result["published"] = pub_result
        return result

    def reject_scan(self, scan_id: str, reviewer: str = "security_manager",
                    comment: str = "No reason given") -> dict:
        """Security manager rejects the scan."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        if scan["status"] not in ("submitted", "under_review"):
            raise ValueError(f"Cannot reject from status '{scan['status']}'")

        scan["status"] = "rejected"
        scan["reviewed_by"] = reviewer
        scan["review_comment"] = comment
        scan["updated_at"] = datetime.now(timezone.utc).isoformat()
        return {"ok": True, "status": "rejected", "scan_id": scan_id}

    # ── Publishing ───────────────────────────────────────────────────────────

    def publish_scan(self, scan_id: str, target_url: str,
                     credential_id: str = "", token: str = "",
                     username: str = "") -> dict:
        """Publish masked repo to git remote."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        session = SESSIONS.get(scan["session_key"])
        if not session:
            raise RuntimeError("Session expired")

        resolved_token = ""
        if credential_id:
            resolved_token = _resolve_credential(credential_id)
        elif token:
            resolved_token = token

        tmp = tempfile.mkdtemp(prefix="lm_pub_")
        try:
            written = 0
            for rel, d in session["files"].items():
                if not _should_publish(rel):
                    continue
                out = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(out) or tmp, exist_ok=True)
                open(out, "w").write(d["masked"])
                written += 1
            _git_push_secure(tmp, target_url, resolved_token, username)
            scan["status"] = "published"
            scan["updated_at"] = datetime.now(timezone.utc).isoformat()
            return {"ok": True, "pushed_to": target_url, "files": written}
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Push failed: {e.stderr.decode()[:400]}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ── Teaching ─────────────────────────────────────────────────────────────

    def teach_value(self, scan_id: str, value: str, action: str = "mask",
                    subtype: str = "SECRET", context_pattern: str = "") -> dict:
        """Teach the system about a value (mask or allow)."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        session = SESSIONS.get(scan.get("session_key", ""))
        if not session:
            raise RuntimeError("Session expired")

        if context_pattern:
            re.compile(context_pattern)  # validate

        if action == "mask":
            teach_info = {"subtype": subtype}
            if context_pattern:
                teach_info["context_pattern"] = context_pattern
            session["taught"][value] = teach_info
            session["allowed"].discard(value)
        else:
            session["allowed"].add(value)
            session["taught"].pop(value, None)
            tok = session["vault"].pop(value, None)
            if tok:
                session["rev_vault"].pop(tok, None)

        _remask(session)
        scan["detections"] = _flatten_detections(session)
        scan["summary_stats"] = _scan_stats(scan["detections"], session)
        scan["updated_at"] = datetime.now(timezone.utc).isoformat()
        return {"ok": True, "action": action, "detection_count": len(scan["detections"])}

    # ── AI Chat ──────────────────────────────────────────────────────────────

    def ask_about_scan(self, scan_id: str, question: str,
                       provider: str = "anthropic",
                       model: str = "claude-sonnet-4-5",
                       source: str = "memory",
                       git_url: str = "") -> dict:
        """Ask AI about a scan. Returns answer with tokens rehydrated."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")

        api_key = KEYS.get(provider, "")
        only_findings = True
        max_chars = 80_000

        session = SESSIONS.get(scan.get("session_key", ""))

        if source == "git":
            repo_url = git_url or scan.get("published", "") or scan.get("publish_target", "")
            if not repo_url:
                raise ValueError("No git URL — provide git_url or publish the scan first")
            credential_id = scan.get("credential_id", "")
            git_token = _resolve_credential(credential_id) if credential_id else ""
        elif not session:
            raise RuntimeError("Session expired — try source: git")

        # Mask the question
        masked_q = _mask_text(session, question) if session else question

        # Per-scan chat history
        history_key = f"messages_{source}"
        history = scan.setdefault(history_key, [])

        prev_key = f"chat_{source}"
        if scan.get(f"{prev_key}_provider") != provider or scan.get(f"{prev_key}_model") != model:
            history.clear()
            scan[f"{prev_key}_provider"] = provider
            scan[f"{prev_key}_model"] = model

        context_loaded = len(history) > 0

        if not context_loaded:
            if source == "git":
                repo_text, truncated = _load_repo_text_from_git(repo_url, git_token, max_chars)
            else:
                repo_text, truncated = _build_repo_context(session, only_findings, max_chars)

            load_msg = (
                "I'm sharing a masked repository with you. "
                "Sensitive values are replaced with tokens like ~[TYPE_N]~. "
                "Never guess or invent real values behind tokens. "
                "Acknowledge with a one-line summary, then wait for my questions.\n\n"
                "MASKED REPOSITORY:\n" + repo_text
            )
            history.append({"role": "user", "content": load_msg})

            if provider == "dry":
                ack = f"[Dry-run] Repo context loaded — {len(repo_text)} chars"
            else:
                if not api_key:
                    raise ValueError(f"No {provider} API key configured")
                ack = _call_model(provider, api_key, model, history)

            history.append({"role": "assistant", "content": ack})

        history.append({"role": "user", "content": masked_q})

        if provider == "dry":
            raw_answer = f"[Dry-run] Would answer: {masked_q}"
        else:
            if not api_key:
                raise ValueError(f"No {provider} API key configured")
            raw_answer = _call_model(provider, api_key, model, history)

        history.append({"role": "assistant", "content": raw_answer})
        answer = _rehydrate(session, raw_answer) if session else raw_answer

        return {
            "status": "OK", "scan_id": scan_id, "source": source,
            "provider": provider, "masked_question": masked_q,
            "answer": answer, "context_loaded": context_loaded,
            "turns": len([m for m in history if m["role"] == "user"]) - (0 if context_loaded else 1),
        }

    def ask_reset(self, scan_id: str) -> dict:
        """Reset AI chat history for a scan."""
        scan = _get_or_load_scan(scan_id)
        if not scan:
            raise KeyError(f"Scan not found: {scan_id}")
        scan["messages_memory"] = []
        scan["messages_git"] = []
        scan.pop("chat_memory_provider", None)
        scan.pop("chat_memory_model", None)
        scan.pop("chat_git_provider", None)
        scan.pop("chat_git_model", None)
        return {"ok": True, "scan_id": scan_id}

    # ── Model Stats ──────────────────────────────────────────────────────────

    def get_model_stats(self) -> dict:
        bert = _get_bert()
        if not bert:
            return {"total_feedback": 0, "learned_rules": 0,
                    "ollama_available": False, "ollama_model": ""}
        return bert.get_stats()

    def retrain_model(self) -> dict:
        bert = _get_bert()
        if not bert:
            raise RuntimeError("Classifier not available")
        return bert.retrain()

    # ── Settings ─────────────────────────────────────────────────────────────

    def set_api_key(self, provider: str, key: str):
        """Set an AI provider API key."""
        if provider not in ("anthropic", "openai", "gemini"):
            raise ValueError(f"Unknown provider: {provider}")
        KEYS[provider] = key

    def get_config(self) -> dict:
        """Get engine configuration."""
        bert = _get_bert()
        return {
            "ollama_available": bert._ollama_available if bert else False,
            "ollama_model": bert._ollama_model if bert else "none",
            "sensitivity_levels": ["minimal", "standard", "strict"],
            "auto_approve": APP_CONFIG,
        }
