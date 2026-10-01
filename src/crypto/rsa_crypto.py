"""RSA key generation and RSA-OAEP (SHA-256) key wrapping."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.errors import WrongKeyError

DEFAULT_KEY_SIZE = 3072


def _oaep() -> padding.OAEP:
    # OAEP is randomized and secure against chosen-ciphertext attacks;
    # textbook / PKCS#1 v1.5 padding is intentionally avoided.
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_rsa_private_key(key_size: int = DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def wrap_key(public_key: rsa.RSAPublicKey, aes_key: bytes) -> bytes:
    return public_key.encrypt(aes_key, _oaep())


def unwrap_key(private_key: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    try:
        return private_key.decrypt(wrapped, _oaep())
    except ValueError:
        # Deliberately vague: do not leak why unwrapping failed.
        raise WrongKeyError(
            "Could not unlock the AES key. The wrong private key was supplied "
            "or the file's key data is damaged."
        ) from None
