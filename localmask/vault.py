"""Credential vault — short-lived encrypted git tokens."""
import hashlib
import os
import secrets
import time


# ── Credential Vault ────────────────────────────────────────────────────────
# Tokens are stored once via /api/credentials, referenced by credential_id.
# They auto-expire after CRED_TTL_SECONDS and are never returned to clients.
CRED_TTL_SECONDS = 3600  # 1 hour
CREDENTIALS: dict = {}   # credential_id → {"token_hash": str, "token_enc": bytes,
                          #                  "created_at": float, "label": str}
_VAULT_KEY = os.environ.get("LOCALMASK_VAULT_KEY", secrets.token_bytes(32).hex())


def _vault_encrypt(plaintext: str) -> bytes:
    """XOR-based obfuscation with HMAC key — not military-grade but prevents
    plain-text exposure in memory dumps. For production use a KMS."""
    key = hashlib.sha256(_VAULT_KEY.encode()).digest()
    pt = plaintext.encode()
    return bytes(p ^ key[i % len(key)] for i, p in enumerate(pt))


def _vault_decrypt(ciphertext: bytes) -> str:
    key = hashlib.sha256(_VAULT_KEY.encode()).digest()
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext)).decode()


def _cred_cleanup():
    """Remove expired credentials."""
    now = time.time()
    expired = [cid for cid, c in CREDENTIALS.items()
               if now - c["created_at"] > CRED_TTL_SECONDS]
    for cid in expired:
        del CREDENTIALS[cid]


def _resolve_credential(credential_id: str) -> str:
    """Look up a credential_id and return the decrypted token, or '' if invalid/expired."""
    _cred_cleanup()
    cred = CREDENTIALS.get(credential_id)
    if not cred:
        return ""
    if time.time() - cred["created_at"] > CRED_TTL_SECONDS:
        del CREDENTIALS[credential_id]
        return ""
    return _vault_decrypt(cred["token_enc"])


