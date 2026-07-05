"""Persistent, encrypted, local mask vault.

Stores token <-> real-value mappings so tokens stay STABLE across scans, syncs,
and process restarts — and so rehydration works even in a fresh process. 100%
local: a SQLite file under ~/.localmask, 0600, gitignored, values encrypted at
rest. Keyed by repo identity so re-scanning the same repo reuses its tokens.

Encryption: uses cryptography's Fernet (AES) when installed; otherwise a
keyed-stream fallback so the free edition still works without the dependency.
Either way the file is local-only and permission-locked. The value->token index
is a salted hash, so plaintext secrets never sit in a lookup column.

Disabled cleanly (in-memory only) if the DB can't be opened — scanning never
breaks because of the store.
"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time

_DIR = os.path.expanduser("~/.localmask")
_DB = os.path.join(_DIR, "vault.sqlite")
_KEY_FILE = os.path.join(_DIR, ".vault_key")


def _load_key() -> bytes:
    os.makedirs(_DIR, exist_ok=True)
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read().strip()
    key = secrets.token_bytes(32)
    with open(_KEY_FILE, "wb") as f:
        f.write(key)
    try:
        os.chmod(_KEY_FILE, 0o600)
    except OSError:
        pass
    return key


def _fernet(key: bytes):
    try:
        import base64
        from cryptography.fernet import Fernet
        return Fernet(base64.urlsafe_b64encode(key))
    except Exception:
        return None


def repo_id_for(src: str) -> str:
    """Stable id for a repo source (URL or path) — the vault namespace."""
    norm = (src or "").rstrip("/").lower()
    norm = norm.replace(".git", "")
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


class VaultStore:
    """Encrypted per-repo token<->value store. Fails soft to disabled."""

    def __init__(self, repo_id: str, db_path: str = _DB):
        self.repo_id = repo_id
        self.enabled = True
        self._key = _load_key()
        self._fernet = _fernet(self._key)
        self.scheme = "fernet" if self._fernet else "xor"
        try:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            self.db = sqlite3.connect(db_path, check_same_thread=False)
            self.db.execute("""CREATE TABLE IF NOT EXISTS vault (
                repo_id TEXT, vhash TEXT, token TEXT, subtype TEXT,
                enc BLOB, scheme TEXT, ts REAL,
                PRIMARY KEY (repo_id, vhash))""")
            self.db.execute("""CREATE INDEX IF NOT EXISTS idx_vault_token
                ON vault(repo_id, token)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS counters (
                repo_id TEXT, ckey TEXT, n INTEGER,
                PRIMARY KEY (repo_id, ckey))""")
            self.db.commit()
            try:
                os.chmod(db_path, 0o600)
            except OSError:
                pass
        except Exception as e:
            print(f"[vault_store] disabled (cannot open {db_path}): {e}")
            self.enabled = False

    # ── crypto ──────────────────────────────────────────────────────────
    def _encrypt(self, value: str) -> bytes:
        if self._fernet:
            return self._fernet.encrypt(value.encode())
        # keyed-stream fallback (obfuscation; file perms are the real guard)
        ks = hashlib.sha256(self._key).digest()
        pt = value.encode()
        return bytes(b ^ ks[i % len(ks)] for i, b in enumerate(pt))

    def _decrypt(self, blob: bytes, scheme: str) -> str:
        if scheme == "fernet" and self._fernet:
            return self._fernet.decrypt(blob).decode()
        ks = hashlib.sha256(self._key).digest()
        return bytes(b ^ ks[i % len(ks)] for i, b in enumerate(blob)).decode(
            errors="replace")

    def _vhash(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()

    # ── mappings ────────────────────────────────────────────────────────
    def put(self, value: str, token: str, subtype: str = ""):
        if not self.enabled:
            return
        try:
            self.db.execute(
                "INSERT OR REPLACE INTO vault VALUES (?,?,?,?,?,?,?)",
                (self.repo_id, self._vhash(value), token, subtype,
                 self._encrypt(value), self.scheme, time.time()))
            self.db.commit()
        except Exception:
            pass

    def hydrate(self, session: dict):
        """Fill session vault/rev_vault/tok_count from the store."""
        if not self.enabled:
            return
        try:
            for token, enc, scheme in self.db.execute(
                    "SELECT token, enc, scheme FROM vault WHERE repo_id=?",
                    (self.repo_id,)):
                value = self._decrypt(enc, scheme)
                session["vault"][value] = token
                session["rev_vault"][token] = value
            for ckey, n in self.db.execute(
                    "SELECT ckey, n FROM counters WHERE repo_id=?",
                    (self.repo_id,)):
                session["tok_count"][ckey] = n
        except Exception as e:
            print(f"[vault_store] hydrate failed: {e}")

    def set_counter(self, ckey: str, n: int):
        if not self.enabled:
            return
        try:
            self.db.execute("INSERT OR REPLACE INTO counters VALUES (?,?,?)",
                            (self.repo_id, ckey, n))
            self.db.commit()
        except Exception:
            pass

    def stats(self) -> dict:
        if not self.enabled:
            return {"enabled": False}
        try:
            n = self.db.execute(
                "SELECT COUNT(*) FROM vault WHERE repo_id=?",
                (self.repo_id,)).fetchone()[0]
        except Exception:
            n = 0
        return {"enabled": True, "scheme": self.scheme, "mappings": n,
                "repo_id": self.repo_id, "db": _DB}
