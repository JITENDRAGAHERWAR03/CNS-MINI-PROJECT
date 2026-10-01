"""RSA key serialization, loading and validation."""
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.rsa_crypto import DEFAULT_KEY_SIZE, generate_rsa_private_key
from src.errors import KeyError_

MIN_KEY_SIZE = 2048


def generate_key_pair(password: Optional[str] = None, key_size: int = DEFAULT_KEY_SIZE):
    """Return (private_pem, public_pem) as bytes.

    If a password is given the private key is encrypted with the library's
    BestAvailableEncryption (PKCS#8). Password strength still matters.
    """
    private = generate_rsa_private_key(key_size)
    if password:
        enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def _check_size(key) -> None:
    if key.key_size < MIN_KEY_SIZE:
        raise KeyError_(f"RSA key is too small ({key.key_size} bits). Minimum is {MIN_KEY_SIZE}.")


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError):
        raise KeyError_("Invalid RSA public key file.") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyError_("Public key is not an RSA key.")
    _check_size(key)
    return key


def load_private_key(pem: bytes, password: Optional[str] = None) -> rsa.RSAPrivateKey:
    pw = password.encode("utf-8") if password else None
    try:
        key = serialization.load_pem_private_key(pem, password=pw)
    except TypeError:
        raise KeyError_("This private key is password-protected. Please enter the password.") from None
    except ValueError:
        msg = "Invalid password or invalid private key file." if pw else "Invalid RSA private key file."
        raise KeyError_(msg) from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyError_("Private key is not an RSA key.")
    _check_size(key)
    return key
