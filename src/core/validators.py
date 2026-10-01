"""Input validation and filename sanitization."""
import re

from src.errors import ValidationError

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB: whole file is held in memory (see limitations)
EXTENSION = ".sfv"
_SAFE = re.compile(r"[^A-Za-z0-9._ -]")


def sanitize_filename(name: str, fallback: str = "decrypted_file") -> str:
    """Return a bare, safe filename. Untrusted names (from a container) can
    contain '../' or absolute paths; we keep only the last path component."""
    name = str(name).replace("\\", "/").split("/")[-1]
    name = _SAFE.sub("_", name).strip(" .")
    name = name.lstrip(".")
    if not name or set(name) <= {"_"}:
        return fallback
    return name[:150]


def validate_size(data: bytes) -> None:
    if len(data) > MAX_FILE_SIZE:
        raise ValidationError(f"File too large (limit {MAX_FILE_SIZE // (1024 * 1024)} MB).")


def validate_sfv_name(name: str) -> None:
    if not str(name).lower().endswith(EXTENSION):
        raise ValidationError("Please select a .sfv encrypted file.")
