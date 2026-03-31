"""Network delay simulation.

We keep the model intentionally simple:
- fixed one-way delay (ms) with optional Gaussian jitter
- optionally sleep in real time, or just return the sampled delay so the
  protocol can account for it in latency metrics without slowing runs.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
import time

from .constants import DEFAULT_LINK_DELAY_MS, DEFAULT_LINK_JITTER_MS


@dataclass(frozen=True, slots=True)
class NetworkConfig:
    delay_ms: float = DEFAULT_LINK_DELAY_MS
    jitter_ms: float = DEFAULT_LINK_JITTER_MS
    seed: int = 123
    real_time: bool = False


class SimulatedNetwork:
    def __init__(self, config: NetworkConfig = NetworkConfig()):
        self._config = config
        self._rng = random.Random(config.seed)

    @property
    def config(self) -> NetworkConfig:
        return self._config

    def transmit(self, payload_bytes: int) -> float:
        """Simulate sending a payload and return the one-way delay in ms."""

        # Payload size isn't used in this simple model, but is passed so you
        # can later upgrade to a bandwidth-based delay model.
        _ = payload_bytes
        d = self._rng.gauss(self._config.delay_ms, self._config.jitter_ms)
        delay_ms = max(0.0, float(d))
        if self._config.real_time and delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        return delay_ms
