"""Performance monitoring (latency + overhead) for protocol phases."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from .models import PhaseMetrics


@dataclass(slots=True)
class PerformanceMonitor:
    phase2: list[PhaseMetrics] = field(default_factory=list)
    phase3: list[PhaseMetrics] = field(default_factory=list)

    def record_phase2(self, metrics: PhaseMetrics) -> None:
        self.phase2.append(metrics)

    def record_phase3(self, metrics: PhaseMetrics) -> None:
        self.phase3.append(metrics)

    def _summarize(self, samples: list[PhaseMetrics]) -> dict[str, float]:
        if not samples:
            return {
                "count": 0,
                "success_rate": 0.0,
                "lat_mean": 0.0,
                "lat_stdev": 0.0,
                "lat_min": 0.0,
                "lat_max": 0.0,
                "compute_mean": 0.0,
                "compute_stdev": 0.0,
                "compute_min": 0.0,
                "compute_max": 0.0,
                "net_mean": 0.0,
                "net_stdev": 0.0,
                "net_min": 0.0,
                "net_max": 0.0,
                "over_mean": 0.0,
            }

        lat = [m.latency_ms for m in samples]
        comp = [m.compute_ms for m in samples]
        net = [m.net_ms for m in samples]
        over = [m.overhead_bytes for m in samples]
        success = [m.success for m in samples]

        return {
            "count": float(len(samples)),
            "success_rate": 100.0 * (sum(1 for s in success if s) / len(success)),
            "lat_mean": statistics.fmean(lat),
            "lat_stdev": statistics.pstdev(lat) if len(lat) > 1 else 0.0,
            "lat_min": min(lat),
            "lat_max": max(lat),
            "compute_mean": statistics.fmean(comp),
            "compute_stdev": statistics.pstdev(comp) if len(comp) > 1 else 0.0,
            "compute_min": min(comp),
            "compute_max": max(comp),
            "net_mean": statistics.fmean(net),
            "net_stdev": statistics.pstdev(net) if len(net) > 1 else 0.0,
            "net_min": min(net),
            "net_max": max(net),
            "over_mean": statistics.fmean(over),
        }

    def report_text(self) -> str:
        p2 = self._summarize(self.phase2)
        p3 = self._summarize(self.phase3)

        def fmt(s: dict[str, float]) -> str:
            if s["count"] == 0:
                return "No samples"
            return (
                f"N={int(s['count'])}, success={s['success_rate']:.1f}%, "
                f"lat(ms) mean={s['lat_mean']:.2f} stdev={s['lat_stdev']:.2f} "
                f"min={s['lat_min']:.2f} max={s['lat_max']:.2f}, "
                f"compute(ms) mean={s['compute_mean']:.3f} stdev={s['compute_stdev']:.3f} "
                f"min={s['compute_min']:.3f} max={s['compute_max']:.3f}, "
                f"net(ms) mean={s['net_mean']:.2f} stdev={s['net_stdev']:.2f} "
                f"min={s['net_min']:.2f} max={s['net_max']:.2f}, "
                f"overhead mean={s['over_mean']:.1f} bytes"
            )

        return "\n".join(
            [
                "================ PERFORMANCE REPORT ================",
                f"Phase 2 (UAV↔GS): {fmt(p2)}",
                f"Phase 3 (UAV↔UAV): {fmt(p3)}",
            ]
        )
