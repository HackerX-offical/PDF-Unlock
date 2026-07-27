"""PDF Standard security handler password verification (R2/R3) + library fallback."""

from __future__ import annotations

import hashlib
from pathlib import Path

from Crypto.Cipher import ARC4

from pdf_unlock.parse import EncryptInfo

# PDF 1.7 Algorithm 3.2 padding string
PADDING = bytes(
    (
        0x28,
        0xBF,
        0x4E,
        0x5E,
        0x4E,
        0x75,
        0x8A,
        0x41,
        0x64,
        0x00,
        0x4E,
        0x56,
        0xFF,
        0xFA,
        0x01,
        0x08,
        0x2E,
        0x2E,
        0x00,
        0xB6,
        0xD0,
        0x68,
        0x3E,
        0x80,
        0x2F,
        0x0C,
        0xA9,
        0xFE,
        0x64,
        0x53,
        0x69,
        0x7A,
    )
)


def _password_bytes(password: str | bytes) -> bytes:
    if isinstance(password, str):
        return password.encode("latin-1", errors="replace")
    return password


def compute_encryption_key(password: str | bytes, info: EncryptInfo) -> bytes:
    """Algorithm 3.2 — derive the file encryption key."""
    pw = (_password_bytes(password) + PADDING)[:32]
    digest = hashlib.md5(pw)
    digest.update(info.o_entry)
    digest.update(info.permissions.to_bytes(4, "little", signed=True))
    digest.update(info.file_id)
    key = digest.digest()
    key_len = info.length // 8
    if info.revision >= 3:
        for _ in range(50):
            key = hashlib.md5(key[:key_len]).digest()
    return key[:key_len]


def check_user_password(password: str | bytes, info: EncryptInfo) -> bool:
    """Algorithm 3.6 — authenticate against the /U entry (R2/R3)."""
    if not info.encrypted:
        return True
    if not info.supports_fast_verify:
        return False

    key = compute_encryption_key(password, info)
    if info.revision == 2:
        return ARC4.new(key).encrypt(PADDING)[:16] == info.u_entry[:16]

    out = ARC4.new(key).encrypt(PADDING)
    for i in range(1, 20):
        out = ARC4.new(bytes(b ^ i for b in key)).encrypt(out)
    return out[:16] == info.u_entry[:16]


def try_open_with_library(path: Path | str, password: str) -> bool:
    """Verify via pikepdf (covers AES / newer revisions)."""
    try:
        import pikepdf
    except ImportError:
        return False
    try:
        with pikepdf.open(path, password=password):
            return True
    except Exception:
        return False


def verify_password(password: str, info: EncryptInfo) -> bool:
    if not info.encrypted:
        return password == ""
    if info.supports_fast_verify and check_user_password(password, info):
        return True
    return try_open_with_library(info.path, password)
