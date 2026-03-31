"""Lightweight cryptographic helpers used by the simulator.

Notes:
- The paper references SPONGENT-160. By default we use Quark (D-Quark)
    truncated to 160 bits *if* a compatible `QUARK.py` module is available.
    Otherwise we fall back to SHA3-256 truncated to 160 bits.
- For "encryption" of small protocol payloads we use a hash-based stream XOR.
    This keeps message sizes aligned with the paper's bit-length accounting.
"""

from __future__ import annotations

import hmac
import os
import secrets
import struct
import time
from typing import Final

from Crypto.Hash import SHA3_256, SHAKE256

from .constants import HASH_BYTES, TS_BYTES


def _bytes_to_bits_msb(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes_msb(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i : i + 8]:
            b = (b << 1) | (1 if bit else 0)
        out.append(b)
    return bytes(out)


_HASH_BACKEND: str | None = None


def hash_backend_name() -> str:
    """Human-readable backend name used for `hash160()`.

    The backend can be forced with env var `UAV_PUF_AUTH_HASH160`:
    - `quark` (requires `QUARK.py` in import path)
    - `sha3`
    """

    global _HASH_BACKEND  # noqa: PLW0603
    if _HASH_BACKEND is None:
        # Initialize lazily by hashing a single byte.
        _ = hash160(b"\x00")
    return _HASH_BACKEND or "unknown"


def hash160(data: bytes) -> bytes:
    """Return a 160-bit digest (20 bytes) of data."""

    global _HASH_BACKEND  # noqa: PLW0603

    forced = os.environ.get("UAV_PUF_AUTH_HASH160", "").strip().lower()
    prefer_quark = forced in {"", "quark", "dquark"}

    if prefer_quark:
        try:
            # QuarkPython is a single-file module named QUARK.py.
            # In this repo we keep it at `uav_puf_auth/QUARK.py`.
            # It requires `numpy` and `bitstring`.
            try:
                from . import QUARK  # type: ignore
            except Exception:  # pragma: no cover
                import QUARK  # type: ignore

            q = QUARK.D_Quark()
            digest_bits = q.keyed_hash(_bytes_to_bits_msb(data), [], output_type="bits")

            # digest_bits is typically a numpy array; normalize to a plain list[int].
            if hasattr(digest_bits, "tolist"):
                digest_list = [int(x) for x in digest_bits.tolist()]
            else:
                digest_list = [int(x) for x in digest_bits]

            digest_bytes = _bits_to_bytes_msb(digest_list)
            _HASH_BACKEND = "quark(d-quark, 176→160)"
            return digest_bytes[:HASH_BYTES]
        except Exception:
            # Fall back to SHA3 below.
            pass

    if forced and forced not in {"sha3", "sha3_256"} and not prefer_quark:
        raise ValueError("UAV_PUF_AUTH_HASH160 must be one of: quark, sha3")

    h = SHA3_256.new(data=data)
    _HASH_BACKEND = "sha3-256(→160)"
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
