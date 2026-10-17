"""V1MMWX wxapkg decryption.

Format (PC WeChat 4.x package cache):
- Plaintext wxapkg starts with 0xBE (pass-through).
- Encrypted wxapkg starts with the ASCII magic "V1MMWX":
  * bytes [6:1030)  — AES-256-CBC, key = PBKDF2-SHA1(appid, salt="saltiest",
    1000 iters, 32 bytes), IV = b"the iv: 16 bytes"; decrypt and keep the
    first 1023 bytes.
  * bytes [1030:]   — XOR with ord(appid[-2]).
  Concatenating both yields the plaintext wxapkg (0xBE header).

Algorithm cross-checked against public wxapkg format research (unveilr,
e0e1-wx) and validated on local WeChat 4.1.15 samples.
"""

from __future__ import annotations

import hashlib
from typing import Final

from Crypto.Cipher import AES

MAGIC: Final = b"V1MMWX"
_SALT: Final = b"saltiest"
_IV: Final = b"the iv: 16 bytes"
_PBKDF2_ITER: Final = 1000
_KEY_LEN: Final = 32
_HEADER_START: Final = 6
_HEADER_END: Final = 1030
_HEADER_PLAIN_LEN: Final = 1023
_PLAINTEXT_MARKER: Final = 0xBE


class WxapkgError(ValueError):
    """Raised when a wxapkg file cannot be decrypted or is malformed."""


def derive_key(app_id: str) -> bytes:
    """Derive the AES-256 key for one appid."""
    return hashlib.pbkdf2_hmac(
        "sha1", app_id.encode("utf-8"), _SALT, _PBKDF2_ITER, _KEY_LEN
    )


def decrypt_wxapkg(data: bytes, app_id: str) -> bytes:
    """Return plaintext wxapkg bytes; plaintext input passes through unchanged."""
    if len(data) < 14:
        raise WxapkgError("file too small to be a wxapkg")
    if data[:6] != MAGIC:
        if data[0] == _PLAINTEXT_MARKER:
            return data
        raise WxapkgError(f"unknown wxapkg magic: {data[:6].hex()}")
    if len(data) < _HEADER_END:
        raise WxapkgError("encrypted wxapkg is too small to carry a full header")

    cipher = AES.new(derive_key(app_id), AES.MODE_CBC, _IV)
    header = cipher.decrypt(data[_HEADER_START:_HEADER_END])[:_HEADER_PLAIN_LEN]
    xor_key = ord(app_id[-2]) if len(app_id) >= 2 else 0
    body = bytes(byte ^ xor_key for byte in data[_HEADER_END:])
    return header + body
