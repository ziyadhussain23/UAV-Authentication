"""Export performance measurements to CSV/text files."""

from __future__ import annotations

import csv
from pathlib import Path

from .models import PhaseMetrics
from .performance import PerformanceMonitor


# Stable, human-readable step columns for CSV (in addition to raw JSON).
PHASE2_STEP_COLUMNS: list[str] = [
    "m1_uav_compute_ms",
    "m1_gs_compute_ms",
    "m1_net_ms",
    "m2_uav_verify_ms",
    "m2_net_ms",
    "puf_eval_ms",
    "bch_ms",
    "m3_crypto_ms",
    "m3_uav_compute_ms",
    "m3_gs_compute_ms",
    "m3_net_ms",
    "m4_uav_compute_ms",
    "m4_net_ms",
]

PHASE3_STEP_COLUMNS: list[str] = [
    "p1_i_compute_ms",
    "p1_p2_j_compute_ms",
    "p1_net_ms",
    "p2_p3_i_compute_ms",
    "p2_net_ms",
    "p3_j_compute_ms",
    "p3_net_ms",
]


def _format_ms(v: float | None) -> str:
    if v is None:
        return ""
    return f"{float(v):.6f}"


def _final_step_columns(samples: list[PhaseMetrics], preferred: list[str]) -> list[str]:
    present = {k for m in samples for k in m.step_ms.keys()}
    extras = sorted(present.difference(preferred))
    return list(preferred) + extras


def export_phase_csv(samples: list[PhaseMetrics], path: Path, *, step_columns: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if step_columns is None:
        step_columns = sorted({k for m in samples for k in m.step_ms.keys()})

    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "idx",
                "success",
                "latency_ms",
                "compute_ms",
                "net_ms",
                "overhead_bytes",
                "details",
                *step_columns,
            ]
        )
        for idx, m in enumerate(samples):
            writer.writerow(
                [
                    idx,
                    int(m.success),
                    f"{m.latency_ms:.6f}",
                    f"{m.compute_ms:.6f}",
                    f"{m.net_ms:.6f}",
                    m.overhead_bytes,
                    m.details,
                    *[_format_ms(m.step_ms.get(k)) for k in step_columns],
                ]
            )


def export_report(monitor: PerformanceMonitor, results_dir: str | Path = "results") -> None:
    out_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    p2_cols = _final_step_columns(monitor.phase2, PHASE2_STEP_COLUMNS)
    p3_cols = _final_step_columns(monitor.phase3, PHASE3_STEP_COLUMNS)

    p2_path = out_dir / "phase2_results.csv"
    p3_path = out_dir / "phase3_results.csv"
    rpt_path = out_dir / "overhead_report.txt"

    export_phase_csv(monitor.phase2, p2_path, step_columns=p2_cols)
    export_phase_csv(monitor.phase3, p3_path, step_columns=p3_cols)
    rpt_path.write_text(monitor.report_text() + "\n")

    print(f"[Results] Wrote {p2_path}")
    print(f"[Results] Wrote {p3_path}")
    print(f"[Results] Wrote {rpt_path}")
