"""Data models for the simulator."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CRPEntry:
    challenge: bytes
    helper_data: bytes
    response_hash: bytes
    consumed: bool = False


@dataclass(slots=True)
class PeerCredential:
    peer_id: int
    peer_tid: bytes
    peer_challenge: bytes
    mask: bytes  # 160-bit


@dataclass(slots=True)
class PhaseMetrics:
    success: bool
    latency_ms: float
    compute_ms: float
    net_ms: float
    overhead_bytes: int
    details: str = ""
    step_ms: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class PerformanceStats:
    samples: list[PhaseMetrics] = field(default_factory=list)

    def add(self, m: PhaseMetrics) -> None:
        self.samples.append(m)
