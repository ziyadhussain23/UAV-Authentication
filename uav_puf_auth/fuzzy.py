"""BCH-based fuzzy extractor helper.

We use bchlib as in the guide:
- BCH(8219, 18): correct up to 18 bit errors

The helper data (ECC bytes) is public and can be stored/transmitted.
"""

from __future__ import annotations

from dataclasses import dataclass

import bchlib


@dataclass(frozen=True, slots=True)
class BCHConfig:
    polynomial: int = 8219
    t: int = 18


class BCHFuzzyExtractor:
    def __init__(self, config: BCHConfig = BCHConfig()):
        self._config = config
        # bchlib's constructor is BCH(t, poly=None, m=None, swap_bits=False)
        # Some wheels don't accept keyword arguments, so we pass poly positionally.
        self._bch = bchlib.BCH(config.t, config.polynomial)

    @property
    def config(self) -> BCHConfig:
        return self._config

    @property
    def ecc_bytes(self) -> int:
        return self._bch.ecc_bytes

    def enroll(self, response: bytes) -> bytes:
        """Return helper data (ECC) for a reference response."""

        return bytes(self._bch.encode(bytearray(response)))

    def reproduce(self, noisy_response: bytes, helper_data: bytes) -> tuple[bytes, int]:
        """Correct noisy_response in-place using helper_data.

        Returns (corrected_response, corrected_bitflips).
        Raises ValueError if too many errors.
        """

        data = bytearray(noisy_response)
        ecc = bytearray(helper_data)

        # bchlib v2 exposes decode() + correct() (decode_inplace() is not always present).
        bitflips = self._bch.decode(data, ecc)
        if bitflips < 0:
            raise ValueError("BCH decode failed (too many bit errors)")

        self._bch.correct(data, ecc)
        return bytes(data), int(bitflips)
