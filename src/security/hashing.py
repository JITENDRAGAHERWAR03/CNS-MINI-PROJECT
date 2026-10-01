"""SHA-256 helpers (educational integrity comparison; AES-GCM is the real protection)."""
import hashlib
import hmac


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashes_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
