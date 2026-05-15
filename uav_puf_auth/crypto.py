"""Lightweight cryptographic helpers used by the simulator.

Notes:
- The paper references SPONGENT-160; we use SHA3-256 truncated to 160 bits.
- For "encryption" of small protocol payloads we use a hash-based stream XOR.
    This keeps message sizes aligned with the paper's bit-length accounting.
"""

from __future__ import annotations

import hmac
import secrets
import struct
import time
from typing import Final

from Crypto.Hash import SHA3_256, SHAKE256

from .constants import HASH_BYTES, TS_BYTES


def hash160(data: bytes) -> bytes:
    """Return a 160-bit digest (20 bytes) of data."""

    h = SHA3_256.new()
    h.update(data)
    return h.digest()[:HASH_BYTES]


def mac160(key: bytes, message: bytes) -> bytes:
    """Compute a lightweight 160-bit MAC as H(key || message)."""

    return hash160(key + message)


def kdf_stream(key: bytes, info: bytes, length: int) -> bytes:
    """Derive a variable-length keystream from key+info using SHAKE256."""

    shake = SHAKE256.new()
    shake.update(key)
    shake.update(info)
    return shake.read(length)


def stream_xor(key: bytes, plaintext_or_ciphertext: bytes, info: bytes = b"") -> bytes:
    """Symmetric XOR stream transform (encrypt/decrypt)."""

    keystream = kdf_stream(key, info=info, length=len(plaintext_or_ciphertext))
    return xor_bytes(plaintext_or_ciphertext, keystream)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes inputs must have same length")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def secure_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality for MAC comparisons."""

    return hmac.compare_digest(a, b)


def rand_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def now_u32() -> int:
    """Current UNIX time in seconds truncated to uint32."""

    return int(time.time()) & 0xFFFFFFFF


def u32_to_bytes(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def bytes_to_u32(data: bytes) -> int:
    if len(data) != TS_BYTES:
        raise ValueError(f"Expected {TS_BYTES} bytes for u32")
    return struct.unpack(">I", data)[0]


ZERO_INFO: Final[bytes] = b""
