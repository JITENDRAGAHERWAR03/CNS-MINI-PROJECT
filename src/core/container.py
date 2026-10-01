"""The .sfv container.

Layout (binary):
    MAGIC "SFV1" (4) | header_len (4, big-endian) | header (JSON, UTF-8)
    | tag (16) | ciphertext (rest)

The header holds only non-secret metadata (nonce, RSA-wrapped AES key, names).
MAGIC + header are passed to AES-GCM as Associated Data, so any change to the
metadata also makes authentication fail. Base64 is used only to fit binary
values into JSON; it gives no security.
"""
import base64
import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from src.core.validators import sanitize_filename, validate_size
from src.crypto import aes_crypto, key_manager, rsa_crypto
from src.errors import ContainerError
from src.security.hashing import sha256_hex

MAGIC = b"SFV1"
VERSION = 1
MAX_HEADER = 16 * 1024


@dataclass
class DecryptResult:
    filename: str
    data: bytes
    sha256: str
    header: dict


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s, field: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise ContainerError(f"Malformed container: bad field '{field}'.") from None


def encrypt_file(data: bytes, filename: str, public_pem: bytes) -> tuple[bytes, dict]:
    """Hybrid-encrypt `data`. Returns (sfv_bytes, info) where info has no secrets."""
    validate_size(data)
    public_key = key_manager.load_public_key(public_pem)
    aes_key = aes_crypto.generate_aes_key()      # fresh key per file
    nonce = aes_crypto.generate_nonce()
    wrapped = rsa_crypto.wrap_key(public_key, aes_key)
    header = {
        "format_version": VERSION,
        "cipher": "AES-256-GCM",
        "key_wrap_algorithm": "RSA-OAEP-SHA256",
        "rsa_key_size": public_key.key_size,
        "nonce": _b64(nonce),
        "encrypted_key": _b64(wrapped),
        "original_filename": sanitize_filename(filename),
        "file_size": len(data),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
    prefix = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes
    ciphertext, tag = aes_crypto.encrypt(aes_key, nonce, data, aad=prefix)
    del aes_key  # drop our reference; Python cannot guarantee memory wiping
    info = dict(header, original_sha256=sha256_hex(data))
    return prefix + tag + ciphertext, info


def parse(blob: bytes) -> tuple[dict, bytes, bytes, bytes]:
    """Validate structure. Returns (header, prefix_aad, tag, ciphertext)."""
    if len(blob) < 8 + aes_crypto.TAG_SIZE or blob[:4] != MAGIC:
        raise ContainerError("Not a valid Secure File Vault (.sfv) file.")
    (hlen,) = struct.unpack(">I", blob[4:8])
    if hlen == 0 or hlen > MAX_HEADER or 8 + hlen + aes_crypto.TAG_SIZE > len(blob):
        raise ContainerError("Malformed container header.")
    try:
        header = json.loads(blob[8:8 + hlen].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ContainerError("Malformed container metadata.") from None
    if not isinstance(header, dict):
        raise ContainerError("Malformed container metadata.")
    if header.get("format_version") != VERSION:
        raise ContainerError("Unsupported container version.")
    if header.get("cipher") != "AES-256-GCM" or header.get("key_wrap_algorithm") != "RSA-OAEP-SHA256":
        raise ContainerError("Unsupported cipher or key-wrap algorithm.")
    for field in ("nonce", "encrypted_key", "original_filename"):
        if field not in header:
            raise ContainerError(f"Malformed container: missing '{field}'.")
    end = 8 + hlen
    return header, blob[:end], blob[end:end + aes_crypto.TAG_SIZE], blob[end + aes_crypto.TAG_SIZE:]


def decrypt_file(blob: bytes, private_pem: bytes, password: str | None = None) -> DecryptResult:
    header, prefix, tag, ciphertext = parse(blob)
    nonce = _unb64(header["nonce"], "nonce")
    if len(nonce) != aes_crypto.NONCE_SIZE:
        raise ContainerError("Malformed container: invalid nonce.")
    wrapped = _unb64(header["encrypted_key"], "encrypted_key")
    private_key = key_manager.load_private_key(private_pem, password)
    aes_key = rsa_crypto.unwrap_key(private_key, wrapped)
    # Raises AuthenticationError on any tampering; no output is produced then.
    plaintext = aes_crypto.decrypt(aes_key, nonce, ciphertext, tag, aad=prefix)
    del aes_key
    return DecryptResult(
        filename=sanitize_filename(header["original_filename"]),  # never trust stored name
        data=plaintext,
        sha256=sha256_hex(plaintext),
        header=header,
    )
