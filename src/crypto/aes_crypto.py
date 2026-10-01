"""AES-256-GCM helpers (built on the `cryptography` library, no custom crypto)."""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.errors import AuthenticationError, ValidationError

KEY_SIZE = 32    # 256-bit key
NONCE_SIZE = 12  # 96-bit nonce: the recommended size for GCM
TAG_SIZE = 16    # 128-bit authentication tag


def generate_aes_key() -> bytes:
    # os.urandom is the OS CSPRNG. `random` module must never be used for keys.
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    # A fresh random nonce per encryption. Reusing a nonce with the same key
    # breaks GCM security, so we never reuse or hardcode one.
    return os.urandom(NONCE_SIZE)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, tag). `aad` is authenticated but not encrypted."""
    if len(key) != KEY_SIZE or len(nonce) != NONCE_SIZE:
        raise ValidationError("Invalid AES key or nonce length.")
    blob = AESGCM(key).encrypt(nonce, plaintext, aad)
    return blob[:-TAG_SIZE], blob[-TAG_SIZE:]  # library appends tag at the end


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """Decrypt and verify the tag. Raises AuthenticationError on ANY mismatch,
    so a corrupted plaintext is never returned."""
    if len(key) != KEY_SIZE or len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
        raise AuthenticationError("Invalid AES key, nonce or tag length.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag:
        raise AuthenticationError(
            "Authentication failed. The encrypted file may have been modified "
            "or the wrong key may have been supplied."
        ) from None
