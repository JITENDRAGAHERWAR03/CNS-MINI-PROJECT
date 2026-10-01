"""User-safe exception types. Messages never contain secrets."""


class VaultError(Exception):
    """Base class for all expected Secure File Vault errors."""


class ValidationError(VaultError):
    """Bad user input (file too large, wrong extension, empty name...)."""


class KeyError_(VaultError):
    """Invalid, unsupported or unreadable RSA key / wrong password."""


class ContainerError(VaultError):
    """Malformed or unsupported .sfv container."""


class WrongKeyError(VaultError):
    """RSA-OAEP unwrap failed: wrong private key or damaged encrypted key."""


class AuthenticationError(VaultError):
    """AES-GCM tag verification failed: data modified or wrong key."""
