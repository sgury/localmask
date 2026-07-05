"""Persistent mask vault — local (SQLite) or shared (Redis).

Stores token <-> real-value mappings so tokens stay STABLE across scans, syncs,
and process restarts, and so rehydration works in a fresh process.

Two backends, one interface:
  * SqliteVaultStore  — 100% local, default. ~/.localmask/vault.sqlite (0600).
  * RedisVaultStore   — shared across a team so everyone gets consistent tokens
                        for the same repo (Team/Enterprise). Uses atomic INCR +
                        HSETNX so concurrent machines never collide.

Both encrypt values at rest and index value->token by a salted HMAC, so no
plaintext secret ever sits in a lookup column. The local backend uses a
per-machine key; the shared backend uses a team key (LOCALMASK_VAULT_KEY) so
every member can decrypt.

Selection: RedisVaultStore when LOCALMASK_VAULT_REDIS_URL is set and the edition
allows it (team+); otherwise SqliteVaultStore. Any failure -> fail soft to the
local store or disabled; scanning never breaks.
"""
import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time

_DIR = os.path.expanduser("~/.localmask")
_DB = os.path.join(_DIR, "vault.sqlite")
_KEY_FILE = os.path.join(_DIR, ".vault_key")


def repo_id_for(src: str) -> str:
    """Stable id for a repo/source. Local paths are canonicalized to their real
    absolute path so the SAME directory always maps to the SAME id regardless of
    how it was referenced (relative vs absolute, trailing slash, or the current
    working directory). Without this, a relative path and its resolved absolute
    form hash differently, and the vault/lexicon key under mismatched ids."""
    s = (src or "").strip()
    is_url = s.startswith(
        ("http://", "https://", "git@", "ssh://", "git://", "file://"))
    if s and not is_url:
        try:
            s = os.path.realpath(os.path.expanduser(s))
        except Exception:
            pass
    norm = s.rstrip("/").lower().replace(".git", "")
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


def _local_key() -> bytes:
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


def _shared_key() -> bytes:
    """Team-shared encryption key (all members must share it to decrypt)."""
    env = os.environ.get("LOCALMASK_VAULT_KEY")
    if env:
        return hashlib.sha256(env.encode()).digest()
    print("[vault_store] WARNING: LOCALMASK_VAULT_KEY not set — the shared vault "
          "needs one common key across the team for at-rest encryption.")
    return hashlib.sha256(b"localmask-default-shared-key").digest()


def _fernet(key: bytes):
    try:
        from cryptography.fernet import Fernet
        return Fernet(base64.urlsafe_b64encode(key))
    except Exception:
        return None


class _Crypto:
    """Shared encryption + hashing for both backends."""

    def _init_crypto(self, key: bytes):
        self._key = key
        self._fernet = _fernet(key)
        self.scheme = "fernet" if self._fernet else "xor"

    def _encrypt(self, value: str) -> bytes:
        if self._fernet:
            return self._fernet.encrypt(value.encode())
        ks = hashlib.sha256(self._key).digest()
        return bytes(b ^ ks[i % len(ks)] for i, b in enumerate(value.encode()))

    def _decrypt(self, blob: bytes, scheme: str) -> str:
        if scheme == "fernet" and self._fernet:
            return self._fernet.decrypt(blob).decode()
        ks = hashlib.sha256(self._key).digest()
        return bytes(b ^ ks[i % len(ks)] for i, b in enumerate(blob)).decode(
            errors="replace")

    def _vhash(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()


class SqliteVaultStore(_Crypto):
    """Local, per-machine encrypted store."""

    def __init__(self, repo_id: str, db_path: str = _DB):
        self.repo_id = repo_id
        self.backend = "sqlite"
        self.enabled = True
        self._init_crypto(_local_key())
        try:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            self.db = sqlite3.connect(db_path, check_same_thread=False)
            self.db.execute("""CREATE TABLE IF NOT EXISTS vault (
                repo_id TEXT, vhash TEXT, token TEXT, subtype TEXT,
                enc BLOB, scheme TEXT, ts REAL, PRIMARY KEY (repo_id, vhash))""")
            self.db.execute("""CREATE INDEX IF NOT EXISTS idx_vault_token
                ON vault(repo_id, token)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS counters (
                repo_id TEXT, ckey TEXT, n INTEGER, PRIMARY KEY (repo_id, ckey))""")
            # User lexicon: values the user taught (mask) or ignored (allow), so
            # they persist across scans/syncs/processes. Encrypted at rest.
            self.db.execute("""CREATE TABLE IF NOT EXISTS lexicon (
                repo_id TEXT, vhash TEXT, action TEXT, subtype TEXT,
                enc BLOB, scheme TEXT, ts REAL, PRIMARY KEY (repo_id, vhash))""")
            self.db.commit()
            try:
                os.chmod(db_path, 0o600)
            except OSError:
                pass
        except Exception as e:
            print(f"[vault_store] sqlite disabled ({e})")
            self.enabled = False

    def token_for(self, value: str):
        if not self.enabled:
            return None
        row = self.db.execute(
            "SELECT token FROM vault WHERE repo_id=? AND vhash=?",
            (self.repo_id, self._vhash(value))).fetchone()
        return row[0] if row else None

    def reserve(self, ckey: str) -> int:
        """Return the next 0-based counter and persist the increment."""
        if not self.enabled:
            return 0
        cur = self.db.execute(
            "SELECT n FROM counters WHERE repo_id=? AND ckey=?",
            (self.repo_id, ckey)).fetchone()
        n = cur[0] if cur else 0
        self.db.execute("INSERT OR REPLACE INTO counters VALUES (?,?,?)",
                        (self.repo_id, ckey, n + 1))
        self.db.commit()
        return n

    def put_if_absent(self, value: str, token: str, subtype: str = "") -> str:
        existing = self.token_for(value)
        if existing:
            return existing
        if self.enabled:
            try:
                self.db.execute(
                    "INSERT OR IGNORE INTO vault VALUES (?,?,?,?,?,?,?)",
                    (self.repo_id, self._vhash(value), token, subtype,
                     self._encrypt(value), self.scheme, time.time()))
                self.db.commit()
            except Exception:
                pass
        return self.token_for(value) or token

    # kept for interface parity / write-through
    def put(self, value: str, token: str, subtype: str = ""):
        self.put_if_absent(value, token, subtype)

    def set_counter(self, ckey: str, n: int):
        if self.enabled:
            self.db.execute("INSERT OR REPLACE INTO counters VALUES (?,?,?)",
                            (self.repo_id, ckey, n))
            self.db.commit()

    def hydrate(self, session: dict):
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

    # ── User lexicon (taught / ignored values) ───────────────────────────────
    def set_lexicon(self, value: str, action: str = "mask",
                    subtype: str = "SECRET"):
        """Persist a user-taught (action='mask') or ignored (action='allow')
        value so it applies on every future scan/sync of this repo."""
        if not self.enabled:
            return
        try:
            self.db.execute(
                "INSERT OR REPLACE INTO lexicon VALUES (?,?,?,?,?,?,?)",
                (self.repo_id, self._vhash(value), action, subtype,
                 self._encrypt(value), self.scheme, time.time()))
            self.db.commit()
        except Exception:
            pass

    def remove_lexicon(self, value: str):
        if not self.enabled:
            return
        try:
            self.db.execute("DELETE FROM lexicon WHERE repo_id=? AND vhash=?",
                            (self.repo_id, self._vhash(value)))
            self.db.commit()
        except Exception:
            pass

    def load_lexicon(self, session: dict):
        """Seed session['taught'] / session['allowed'] from the persisted lexicon."""
        if not self.enabled:
            return
        try:
            for action, subtype, enc, scheme in self.db.execute(
                    "SELECT action, subtype, enc, scheme FROM lexicon "
                    "WHERE repo_id=?", (self.repo_id,)):
                value = self._decrypt(enc, scheme)
                if action == "mask":
                    session.setdefault("taught", {})[value] = {
                        "subtype": subtype or "SECRET"}
                    session.setdefault("allowed", set()).discard(value)
                else:
                    session.setdefault("allowed", set()).add(value)
                    session.setdefault("taught", {}).pop(value, None)
        except Exception as e:
            print(f"[vault_store] load_lexicon failed: {e}")

    def stats(self) -> dict:
        n = 0
        if self.enabled:
            try:
                n = self.db.execute("SELECT COUNT(*) FROM vault WHERE repo_id=?",
                                    (self.repo_id,)).fetchone()[0]
            except Exception:
                pass
        return {"backend": "sqlite", "enabled": self.enabled,
                "scheme": self.scheme, "mappings": n, "repo_id": self.repo_id}


class RedisVaultStore(_Crypto):
    """Shared, team-wide store. Atomic INCR + HSETNX make concurrent minting
    across machines collision-free."""

    def __init__(self, repo_id: str, url: str):
        self.repo_id = repo_id
        self.backend = "redis"
        self.enabled = True
        self._init_crypto(_shared_key())
        try:
            import redis
            self.r = redis.from_url(url)
            self.r.ping()
        except Exception as e:
            print(f"[vault_store] redis unavailable ({e}) — falling back to local")
            self.enabled = False

    def _k(self, suffix: str) -> str:
        return f"lm:vault:{self.repo_id}:{suffix}"

    def token_for(self, value: str):
        if not self.enabled:
            return None
        v = self.r.hget(self._k("v2t"), self._vhash(value))
        return v.decode() if v else None

    def reserve(self, ckey: str) -> int:
        if not self.enabled:
            return 0
        return int(self.r.incr(self._k(f"ctr:{ckey}"))) - 1   # 0-based

    def put_if_absent(self, value: str, token: str, subtype: str = "") -> str:
        if not self.enabled:
            return token
        vh = self._vhash(value)
        if self.r.hsetnx(self._k("v2t"), vh, token):      # we won the race
            self.r.hset(self._k("enc"), token, self._encrypt(value))
            if subtype:
                self.r.hset(self._k("sub"), token, subtype)
            return token
        won = self.r.hget(self._k("v2t"), vh)             # someone beat us
        return won.decode() if won else token

    def put(self, value: str, token: str, subtype: str = ""):
        self.put_if_absent(value, token, subtype)

    def set_counter(self, ckey: str, n: int):
        # counters advance via reserve()/INCR; only bump forward, never back
        if self.enabled:
            cur = self.r.get(self._k(f"ctr:{ckey}"))
            if cur is None or int(cur) < n:
                self.r.set(self._k(f"ctr:{ckey}"), n)

    def hydrate(self, session: dict):
        if not self.enabled:
            return
        try:
            for token_b, enc in self.r.hgetall(self._k("enc")).items():
                token = token_b.decode()
                value = self._decrypt(enc, self.scheme)
                session["vault"][value] = token
                session["rev_vault"][token] = value
            for k in self.r.scan_iter(self._k("ctr:*")):
                ckey = k.decode().rsplit(":ctr:", 1)[-1]
                session["tok_count"][ckey] = int(self.r.get(k))
        except Exception as e:
            print(f"[vault_store] redis hydrate failed: {e}")

    # ── User lexicon (taught / ignored values), shared across the team ────────
    def set_lexicon(self, value: str, action: str = "mask",
                    subtype: str = "SECRET"):
        if not self.enabled:
            return
        vh = self._vhash(value)
        self.r.hset(self._k("lex"), vh, action)
        self.r.hset(self._k("lexenc"), vh, self._encrypt(value))
        self.r.hset(self._k("lexsub"), vh, subtype or "SECRET")

    def remove_lexicon(self, value: str):
        if not self.enabled:
            return
        vh = self._vhash(value)
        self.r.hdel(self._k("lex"), vh)
        self.r.hdel(self._k("lexenc"), vh)
        self.r.hdel(self._k("lexsub"), vh)

    def load_lexicon(self, session: dict):
        if not self.enabled:
            return
        try:
            actions = self.r.hgetall(self._k("lex"))
            encs = self.r.hgetall(self._k("lexenc"))
            subs = self.r.hgetall(self._k("lexsub"))
            for vh_b, action_b in actions.items():
                action = action_b.decode()
                enc = encs.get(vh_b)
                if enc is None:
                    continue
                value = self._decrypt(enc, self.scheme)
                if action == "mask":
                    subtype = subs.get(vh_b, b"SECRET").decode()
                    session.setdefault("taught", {})[value] = {"subtype": subtype}
                    session.setdefault("allowed", set()).discard(value)
                else:
                    session.setdefault("allowed", set()).add(value)
                    session.setdefault("taught", {}).pop(value, None)
        except Exception as e:
            print(f"[vault_store] redis load_lexicon failed: {e}")

    def stats(self) -> dict:
        n = 0
        if self.enabled:
            try:
                n = self.r.hlen(self._k("enc"))
            except Exception:
                pass
        return {"backend": "redis", "enabled": self.enabled,
                "scheme": self.scheme, "mappings": n, "repo_id": self.repo_id}


def get_vault_store(repo_id: str):
    """Pick the shared Redis store when configured + allowed, else local SQLite.
    Fails soft to SQLite so scanning never breaks."""
    url = os.environ.get("LOCALMASK_VAULT_REDIS_URL")
    if url:
        try:
            from ._edition import has_capability
            allowed = has_capability("shared_vault")
        except Exception:
            allowed = True
        if allowed:
            store = RedisVaultStore(repo_id, url)
            if store.enabled:
                return store
            print("[vault_store] using local SQLite (redis not reachable)")
    return SqliteVaultStore(repo_id)


# Back-compat alias
VaultStore = SqliteVaultStore
