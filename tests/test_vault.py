"""Secure File Vault tests. Run with: pytest -v"""
import os

import pytest

from src.core import container
from src.core.validators import sanitize_filename, validate_sfv_name
from src.crypto import aes_crypto, key_manager, rsa_crypto
from src.errors import (AuthenticationError, ContainerError, KeyError_,
                        ValidationError, VaultError, WrongKeyError)
from src.security.hashing import hashes_match, sha256_hex

_CACHE = {}


def keys(name="a", password=None):
    k = (name, password)
    if k not in _CACHE:
        _CACHE[k] = key_manager.generate_key_pair(password)
    return _CACHE[k]


def roundtrip(data: bytes, name="f.bin"):
    priv, pub = keys()
    blob, _ = container.encrypt_file(data, name, pub)
    return blob, container.decrypt_file(blob, priv)


# --- primitives -------------------------------------------------------
def test_rsa_key_generation():
    priv, pub = keys()
    assert b"BEGIN PRIVATE KEY" in priv and b"BEGIN PUBLIC KEY" in pub
    assert key_manager.load_public_key(pub).key_size == 3072


def test_aes_key_and_nonce_are_random_and_sized():
    assert len(aes_crypto.generate_aes_key()) == 32
    assert aes_crypto.generate_aes_key() != aes_crypto.generate_aes_key()
    assert aes_crypto.generate_nonce() != aes_crypto.generate_nonce()


def test_aes_roundtrip_and_tamper():
    k, n = aes_crypto.generate_aes_key(), aes_crypto.generate_nonce()
    ct, tag = aes_crypto.encrypt(k, n, b"hello", b"aad")
    assert aes_crypto.decrypt(k, n, ct, tag, b"aad") == b"hello"
    with pytest.raises(AuthenticationError):
        aes_crypto.decrypt(k, n, ct, tag, b"other-aad")


def test_rsa_oaep_roundtrip_and_wrong_key():
    priv, pub = keys()
    aes = aes_crypto.generate_aes_key()
    w = rsa_crypto.wrap_key(key_manager.load_public_key(pub), aes)
    assert rsa_crypto.unwrap_key(key_manager.load_private_key(priv), w) == aes
    other_priv, _ = keys("b")
    with pytest.raises(WrongKeyError):
        rsa_crypto.unwrap_key(key_manager.load_private_key(other_priv), w)


# --- hybrid -----------------------------------------------------------
def test_text_binary_empty_and_large_files():
    for data in (b"plain text\n", os.urandom(5000), b"", os.urandom(3 * 1024 * 1024)):
        blob, res = roundtrip(data)
        assert res.data == data
        assert data not in blob or data == b""


def test_hash_comparison():
    data = os.urandom(1000)
    _, res = roundtrip(data)
    assert hashes_match(sha256_hex(data), res.sha256)
    assert not hashes_match(sha256_hex(data), sha256_hex(data + b"x"))


def test_wrong_private_key_rejected():
    _, pub = keys()
    blob, _ = container.encrypt_file(b"secret", "a.txt", pub)
    other_priv, _ = keys("b")
    with pytest.raises(WrongKeyError):
        container.decrypt_file(blob, other_priv)


def _flip(blob, idx):
    b = bytearray(blob)
    b[idx] ^= 0x01
    return bytes(b)


def test_modified_ciphertext_and_tag_rejected():
    priv, pub = keys()
    blob, _ = container.encrypt_file(b"important data" * 10, "a.txt", pub)
    with pytest.raises(AuthenticationError):
        container.decrypt_file(_flip(blob, len(blob) - 1), priv)   # ciphertext
    hlen = int.from_bytes(blob[4:8], "big")
    with pytest.raises(AuthenticationError):
        container.decrypt_file(_flip(blob, 8 + hlen), priv)         # tag


def test_modified_metadata_rejected():
    priv, pub = keys()
    blob, _ = container.encrypt_file(b"data", "report.txt", pub)
    tampered = blob.replace(b"report.txt", b"reporT.txt")
    with pytest.raises(VaultError):
        container.decrypt_file(tampered, priv)


def test_invalid_containers():
    priv, pub = keys()
    for bad in (b"", b"not a container at all", b"SFV1" + b"\xff" * 40):
        with pytest.raises(ContainerError):
            container.decrypt_file(bad, priv)


def test_password_protected_private_key():
    priv, pub = keys("pw", "correct horse battery staple")
    assert b"ENCRYPTED" in priv
    blob, _ = container.encrypt_file(b"x", "a.txt", pub)
    assert container.decrypt_file(blob, priv, "correct horse battery staple").data == b"x"
    with pytest.raises(KeyError_):
        container.decrypt_file(blob, priv, "wrong")
    with pytest.raises(KeyError_):
        container.decrypt_file(blob, priv)


def test_invalid_keys():
    with pytest.raises(KeyError_):
        key_manager.load_public_key(b"junk")
    with pytest.raises(KeyError_):
        key_manager.load_private_key(b"junk")


# --- validation -------------------------------------------------------
def test_filename_sanitization_and_path_traversal():
    assert sanitize_filename("../../malicious.exe") == "malicious.exe"
    assert sanitize_filename("..\\..\\windows\\evil.dll") == "evil.dll"
    assert sanitize_filename("/etc/passwd") == "passwd"
    assert sanitize_filename("..") == "decrypted_file"
    assert "/" not in sanitize_filename("a/b\x00c")


def test_malicious_stored_filename_is_neutralised():
    _, pub = keys()
    priv, _ = keys()
    blob, _ = container.encrypt_file(b"d", "../../evil.sh", pub)
    assert container.decrypt_file(blob, priv).filename == "evil.sh"


def test_extension_validation():
    validate_sfv_name("a.pdf.sfv")
    with pytest.raises(ValidationError):
        validate_sfv_name("a.pdf")
