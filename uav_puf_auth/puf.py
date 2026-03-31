"""PUF simulation wrapper.

We use a 1-bit ArbiterPUF (pypuf) and derive a 128-bit response by
repeating evaluations on 128 sub-challenges deterministically derived
from a 128-bit seed challenge.

This preserves the paper-style on-wire challenge size (128 bits) while
still producing a multi-bit response suitable for BCH + hashing.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from Crypto.Hash import SHAKE256
from pypuf.simulation import ArbiterPUF

from .constants import CHALLENGE_BITS, CHALLENGE_BYTES, RESPONSE_BITS, RESPONSE_BYTES


@dataclass(frozen=True, slots=True)
class PUFConfig:
    stages: int = CHALLENGE_BITS
    response_bits: int = RESPONSE_BITS
    seed: int = 42
    noisiness: float = 0.03


class PUFSimulator:
    def __init__(self, config: PUFConfig):
        if config.stages != CHALLENGE_BITS:
            raise ValueError(f"This simulator expects {CHALLENGE_BITS}-bit challenges")
        if config.response_bits % 8 != 0:
            raise ValueError("response_bits must be a multiple of 8")
        self._config = config
        self._puf = ArbiterPUF(n=config.stages, seed=config.seed, noisiness=config.noisiness)

    @property
    def config(self) -> PUFConfig:
        return self._config

    def evaluate(self, challenge_seed: bytes) -> bytes:
        """Evaluate a 128-bit seed challenge and return a RESPONSE_BITS-bit response."""

        if len(challenge_seed) != CHALLENGE_BYTES:
            raise ValueError(f"challenge_seed must be {CHALLENGE_BYTES} bytes")

        sub = self._derive_subchallenges(challenge_seed, count=self._config.response_bits)
        resp = self._puf.eval(sub)

        # pypuf returns values in {-1, +1}. Convert to 0/1 bits.
        resp_bits = (np.asarray(resp) > 0).astype(np.uint8)
        packed = np.packbits(resp_bits, bitorder="big")
        out = packed.tobytes()

        if len(out) != RESPONSE_BYTES:
            raise RuntimeError(f"Unexpected response length: {len(out)} bytes")
        return out

    def evaluate_stable(self, challenge_seed: bytes, samples: int = 5) -> bytes:
        """Return a majority-vote response across multiple noisy evaluations."""

        if samples <= 0:
            raise ValueError("samples must be >= 1")

        responses = np.zeros((samples, self._config.response_bits), dtype=np.uint8)
        for i in range(samples):
            r = self.evaluate(challenge_seed)
            bits = np.unpackbits(np.frombuffer(r, dtype=np.uint8), bitorder="big")
            responses[i, :] = bits

        majority = (responses.sum(axis=0) >= ((samples // 2) + 1)).astype(np.uint8)
        packed = np.packbits(majority, bitorder="big")
        return packed.tobytes()

    def _derive_subchallenges(self, seed: bytes, count: int) -> np.ndarray:
        # Each subchallenge is 128 bits (16 bytes). Generate count*16 bytes deterministically.
        shake = SHAKE256.new(data=seed)
        raw = shake.read(count * CHALLENGE_BYTES)
        byte_arr = np.frombuffer(raw, dtype=np.uint8).reshape(count, CHALLENGE_BYTES)

        # Unpack to bits (0/1) then map to {-1, +1}.
        bits = np.unpackbits(byte_arr, axis=1, bitorder="big").astype(np.int8)
        return bits * 2 - 1
