"""High-level simulation runners.

These functions reproduce the guide-style tests:
- Single authentication
- Swarm authentication (multiple UAVs)
- Benchmark loop (many iterations)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Sequence

from .constants import DEFAULT_NUM_CRPS
from .crypto import hash_backend_name
from .entities import GroundStation, UAV
from .export import export_report
from .network import NetworkConfig, SimulatedNetwork
from .performance import PerformanceMonitor
from .storage import save_gs_state, save_uav_state
from .visualization import plot_compute_vs_network_breakdown, plot_latency_histogram


def _print_kv(items: Sequence[tuple[str, str]], *, indent: str = "  ") -> None:
    filtered: list[tuple[str, str]] = [(k, str(v)) for k, v in items if str(v).strip()]
    if not filtered:
        return
    width = max(len(k) for k, _ in filtered)
    for k, v in filtered:
        print(f"{indent}{k.ljust(width)} : {v}")


def _render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    indent: str = "  ",
    align: Sequence[str] | None = None,
) -> None:
    rows_list = [list(map(str, r)) for r in rows]
    headers_list = list(map(str, headers))
    if align is None:
        align = ["<"] * len(headers_list)
    if len(align) != len(headers_list):
        raise ValueError("align must match headers length")

    cols = [headers_list] + rows_list
    widths = [max(len(row[i]) for row in cols) for i in range(len(headers_list))]

    def fmt_row(row: Sequence[str]) -> str:
        parts: list[str] = []
        for i, cell in enumerate(row):
            spec = align[i]
            if spec == ">":
                parts.append(str(cell).rjust(widths[i]))
            else:
                parts.append(str(cell).ljust(widths[i]))
        return indent + "  ".join(parts)

    print(fmt_row(headers_list))
    print(indent + "  ".join("-" * w for w in widths))
    for r in rows_list:
        print(fmt_row(r))


def _should_show_plots() -> bool:
    # Showing plot windows can stop/hang in some terminals.
    # Default: save plots only. Enable showing explicitly via env var.
    enabled = os.environ.get("UAV_PUF_AUTH_SHOW_PLOTS", "").strip().lower() in {"1", "true", "yes"}
    if not enabled:
        return False
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _save_provisioning(gs: GroundStation, uavs: list[UAV], out_dir: str | Path = "provisioning") -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    gs_path = save_gs_state(gs, out_dir / "gs_state.json")
    print(f"[Provision] Wrote {gs_path}")
    for uav in uavs:
        uav_path = save_uav_state(uav, out_dir / f"uav_{uav.node_id}.json")
        print(f"[Provision] Wrote {uav_path}")
    print()


def _plot_and_save(monitor: PerformanceMonitor, results_dir: str | Path = "results") -> None:
    out_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    show = _should_show_plots()

    phase2_lat = [m.latency_ms for m in monitor.phase2 if m.success]
    phase3_lat = [m.latency_ms for m in monitor.phase3 if m.success]
    phase2_comp = [m.compute_ms for m in monitor.phase2 if m.success]
    phase2_net = [m.net_ms for m in monitor.phase2 if m.success]
    phase3_comp = [m.compute_ms for m in monitor.phase3 if m.success]
    phase3_net = [m.net_ms for m in monitor.phase3 if m.success]

    try:
        p1 = plot_latency_histogram(
            phase2_lat,
            phase3_lat,
            out_path=out_dir / "latency_distribution.png",
            show=show,
        )
        p2 = plot_compute_vs_network_breakdown(
            phase2_comp,
            phase2_net,
            phase3_comp,
            phase3_net,
            out_path=out_dir / "compute_vs_network.png",
            show=show,
        )
    except Exception as e:
        print(f"[Plots] Skipped plotting (error: {e})")
        return

    print(f"[Plots] Saved {p1}")
    print(f"[Plots] Saved {p2}")
    if show:
        print("[Plots] Displayed plot window(s).")
    else:
        print("[Plots] Plots saved (set UAV_PUF_AUTH_SHOW_PLOTS=1 to display windows).")
    print()


def _print_step_timing_phase2(m2, *, label: str | None = None, indent: str = "") -> None:
    s = m2.step_ms
    g = lambda k: float(s.get(k, 0.0))

    m1_compute = g("m1_uav_compute_ms") + g("m1_gs_compute_ms")
    m2_compute = g("m2_uav_verify_ms")
    m3_uav_parts = g("puf_eval_ms") + g("bch_ms") + g("m3_crypto_ms")
    m3_compute = m3_uav_parts + g("m3_gs_compute_ms")
    m4_compute = g("m4_uav_compute_ms")

    m1_net = g("m1_net_ms")
    m2_net = g("m2_net_ms")
    m3_net = g("m3_net_ms")
    m4_net = g("m4_net_ms")

    title = "[Phase 2] Step timing (compute vs network)" if not label else f"{label} step timing (compute vs network)"
    print(f"{indent}{title}")

    headers = ["Step", "Compute (ms)", "Net (ms)", "Total (ms)", "Notes"]
    rows = [
        [
            "M1 (UAV→GS)",
            f"{m1_compute:.3f}",
            f"{m1_net:.2f}",
            f"{(m1_compute + m1_net):.2f}",
            f"uav={g('m1_uav_compute_ms'):.3f}, gs={g('m1_gs_compute_ms'):.3f}",
        ],
        [
            "M2 (GS→UAV)",
            f"{m2_compute:.3f}",
            f"{m2_net:.2f}",
            f"{(m2_compute + m2_net):.2f}",
            f"uav_verify={g('m2_uav_verify_ms'):.3f}",
        ],
        [
            "M3 (UAV→GS)",
            f"{m3_compute:.3f}",
            f"{m3_net:.2f}",
            f"{(m3_compute + m3_net):.2f}",
            (
                f"puf={g('puf_eval_ms'):.3f}, bch={g('bch_ms'):.3f}, crypto={g('m3_crypto_ms'):.3f}, "
                f"gs={g('m3_gs_compute_ms'):.3f}"
            ),
        ],
        [
            "M4 (GS→UAV)",
            f"{m4_compute:.3f}",
            f"{m4_net:.2f}",
            f"{(m4_compute + m4_net):.2f}",
            f"uav={g('m4_uav_compute_ms'):.3f}",
        ],
        [
            "TOTAL",
            f"{m2.compute_ms:.3f}",
            f"{m2.net_ms:.2f}",
            f"{m2.latency_ms:.2f}",
            "",
        ],
    ]

    _render_table(headers, rows, indent=indent + "  ", align=["<", ">", ">", ">", "<"])
    print()


def _print_step_timing_phase3(m3, *, label: str | None = None, indent: str = "") -> None:
    s = m3.step_ms
    g = lambda k: float(s.get(k, 0.0))

    p1_compute = g("p1_i_compute_ms") + g("p1_p2_j_compute_ms")
    p2_compute = g("p2_p3_i_compute_ms")
    p3_compute = g("p3_j_compute_ms")

    p1_net = g("p1_net_ms")
    p2_net = g("p2_net_ms")
    p3_net = g("p3_net_ms")

    title = "[Phase 3] Step timing (compute vs network)" if not label else f"{label} step timing (compute vs network)"
    print(f"{indent}{title}")

    headers = ["Step", "Compute (ms)", "Net (ms)", "Total (ms)", "Notes"]
    rows = [
        [
            "P1 (i→j)",
            f"{p1_compute:.3f}",
            f"{p1_net:.2f}",
            f"{(p1_compute + p1_net):.2f}",
            f"i={g('p1_i_compute_ms'):.3f}, j={g('p1_p2_j_compute_ms'):.3f}",
        ],
        [
            "P2 (j→i)",
            f"{p2_compute:.3f}",
            f"{p2_net:.2f}",
            f"{(p2_compute + p2_net):.2f}",
            f"i={g('p2_p3_i_compute_ms'):.3f}",
        ],
        [
            "P3 (i→j)",
            f"{p3_compute:.3f}",
            f"{p3_net:.2f}",
            f"{(p3_compute + p3_net):.2f}",
            f"j={g('p3_j_compute_ms'):.3f}",
        ],
        [
            "TOTAL",
            f"{m3.compute_ms:.3f}",
            f"{m3.net_ms:.2f}",
            f"{m3.latency_ms:.2f}",
            "",
        ],
    ]

    _render_table(headers, rows, indent=indent + "  ", align=["<", ">", ">", ">", "<"])
    print()


def _print_phase2_accounting() -> None:
    # Paper accounting: 64 + 32 + 128 + 160 = 384 bits = 48 bytes
    #                 128 + 128 + 160 + 32 = 448 bits = 56 bytes
    #                 128 + 160 + 128 + 32 = 448 bits = 56 bytes
    # Total target: 1680 bits ≈ 210 bytes
    msg1 = 48
    msg2 = 56
    msg3 = 56
    msg4 = 210 - (msg1 + msg2 + msg3)
    print("[Phase 2] Message size accounting (paper-style)")
    print(f"  M1 (UAV→GS): {msg1} bytes")
    print(f"  M2 (GS→UAV): {msg2} bytes")
    print(f"  M3 (UAV→GS): {msg3} bytes")
    print(f"  M4 (GS→UAV): {msg4} bytes")
    print(f"  Total: {msg1 + msg2 + msg3 + msg4} bytes")
    print()


def _print_phase3_accounting() -> None:
    # Paper accounting total: 1568 bits ≈ 196 bytes
    # P1: 64 + 128 + 160 + 160 + 32 = 544 bits = 68 bytes
    # P2: 512 bits = 64 bytes
    # P3: 512 bits = 64 bytes
    p1, p2, p3 = 68, 64, 64
    print("[Phase 3] Message size accounting (paper-style)")
    print(f"  P1 (UAVi→UAVj): {p1} bytes")
    print(f"  P2 (UAVj→UAVi): {p2} bytes")
    print(f"  P3 (UAVi→UAVj): {p3} bytes")
    print(f"  Total: {p1 + p2 + p3} bytes")
    print()


def _print_header() -> None:
    print("=" * 64)
    print(" PUF-BASED UAV AUTHENTICATION PROTOCOL")
    print(" Modular Simulation Implementation")
    print("=" * 64)
    print(f"[Crypto] hash160 backend: {hash_backend_name()}")
    print()


def run_single_authentication_test() -> PerformanceMonitor:
    _print_header()

    _print_phase2_accounting()

    monitor = PerformanceMonitor()
    gs = GroundStation(node_id=1000)

    network_gs_cfg = NetworkConfig(delay_ms=5.0, jitter_ms=0.0, seed=1, real_time=False)
    network_gs = SimulatedNetwork(network_gs_cfg)
    print(f"[Network] GS link: delay={network_gs_cfg.delay_ms} ms, jitter={network_gs_cfg.jitter_ms} ms (one-way)")
    print()

    uav = UAV(node_id=1, puf_seed=42)
    gs.enroll_uav(uav, num_crps=DEFAULT_NUM_CRPS)
    print(f"[GS] Enrolled UAV {uav.node_id} with {DEFAULT_NUM_CRPS} CRPs")

    _save_provisioning(gs, [uav], out_dir="provisioning")

    print("[Phase 2] UAV authenticating with Ground Station...")
    m2 = uav.phase2_authenticate_with_gs(gs, network_gs)
    monitor.record_phase2(m2)

    status = "✓ SUCCESS" if m2.success else "✗ FAIL"
    print("[Phase 2] Result")
    _print_kv(
        [
            ("Status", status),
            ("Latency", f"{m2.latency_ms:.2f} ms"),
            ("Compute", f"{m2.compute_ms:.3f} ms"),
            ("Network", f"{m2.net_ms:.2f} ms"),
            ("Overhead", f"{m2.overhead_bytes} bytes"),
            ("Details", m2.details or ""),
        ]
    )
    print()

    _print_step_timing_phase2(m2)

    print(monitor.report_text())
    export_report(monitor, results_dir="results")
    _plot_and_save(monitor, results_dir="results")
    return monitor


def run_swarm_authentication_test(num_uavs: int = 5) -> PerformanceMonitor:
    _print_header()

    _print_phase2_accounting()
    _print_phase3_accounting()

    monitor = PerformanceMonitor()
    gs = GroundStation(node_id=1000)

    network_gs_cfg = NetworkConfig(delay_ms=5.0, jitter_ms=0.0, seed=2, real_time=False)
    network_peer_cfg = NetworkConfig(delay_ms=1.0, jitter_ms=0.0, seed=3, real_time=False)
    network_gs = SimulatedNetwork(network_gs_cfg)
    network_peer = SimulatedNetwork(network_peer_cfg)
    print(f"[Network] GS link: delay={network_gs_cfg.delay_ms} ms, jitter={network_gs_cfg.jitter_ms} ms (one-way)")
    print(f"[Network] Peer link: delay={network_peer_cfg.delay_ms} ms, jitter={network_peer_cfg.jitter_ms} ms (one-way)")
    print()

    uavs = [UAV(node_id=i + 1, puf_seed=100 + i) for i in range(num_uavs)]

    for uav in uavs:
        gs.enroll_uav(uav, num_crps=DEFAULT_NUM_CRPS)

    print(f"[GS] Enrolled {num_uavs} UAVs (each with {DEFAULT_NUM_CRPS} CRPs)")
    print()

    _save_provisioning(gs, uavs, out_dir="provisioning")

    print("[TEST] Swarm Phase 2 Authentication")
    phase2_results = []
    for uav in uavs:
        m2 = uav.phase2_authenticate_with_gs(gs, network_gs)
        monitor.record_phase2(m2)
        phase2_results.append(m2)

    rows = []
    for uav, m2 in zip(uavs, phase2_results, strict=True):
        rows.append(
            [
                str(uav.node_id),
                "✓" if m2.success else "✗",
                f"{m2.latency_ms:.2f}",
                f"{m2.compute_ms:.3f}",
                f"{m2.net_ms:.2f}",
                str(m2.overhead_bytes),
                m2.details,
            ]
        )

    print("[Phase 2] Summary")
    _render_table(
        ["UAV", "OK", "Total (ms)", "Compute (ms)", "Net (ms)", "Overhead (B)", "Details"],
        rows,
        align=[">", "<", ">", ">", ">", ">", "<"],
    )
    print()

    print("[Phase 2] Step breakdowns")
    for uav, m2 in zip(uavs, phase2_results, strict=True):
        _print_step_timing_phase2(m2, label=f"UAV {uav.node_id}", indent="  ")

    authed_uavs = [u for u, m in zip(uavs, phase2_results, strict=True) if m.success]
    if len(authed_uavs) < len(uavs):
        print(f"[WARN] Only {len(authed_uavs)}/{len(uavs)} UAVs authenticated; Phase 3 will run for successful UAVs only.")
        print()

    if len(authed_uavs) >= 2:
        # After Phase 2, compute peer credentials for Phase 3.
        gs.build_peer_credentials(authed_uavs)

        print(f"[TEST] Phase 3 Peer Authentication (full mesh: {len(authed_uavs)} UAVs)")
        pair_results: list[tuple[str, object]] = []
        for i in range(len(authed_uavs)):
            for j in range(i + 1, len(authed_uavs)):
                a = authed_uavs[i]
                b = authed_uavs[j]
                label = f"UAV{a.node_id}↔UAV{b.node_id}"
                m3 = a.phase3_authenticate_with_peer(b, network_peer)
                m3.details = f"pair={label}; {m3.details}".strip()
                monitor.record_phase3(m3)
                pair_results.append((label, m3))

        print("[Phase 3] Summary")
        _render_table(
            ["Pair", "OK", "Total (ms)", "Compute (ms)", "Net (ms)", "Overhead (B)", "Details"],
            [
                [
                    label,
                    "✓" if m3.success else "✗",
                    f"{m3.latency_ms:.2f}",
                    f"{m3.compute_ms:.3f}",
                    f"{m3.net_ms:.2f}",
                    str(m3.overhead_bytes),
                    m3.details,
                ]
                for label, m3 in pair_results
            ],
            align=["<", "<", ">", ">", ">", ">", "<"],
        )
        print()

        print("[Phase 3] Step breakdowns")
        for label, m3 in pair_results:
            _print_step_timing_phase3(m3, label=label, indent="  ")

        print(f"[Phase 3] Completed {len(pair_results)} pair authentications")
        print()

    print(monitor.report_text())
    export_report(monitor, results_dir="results")
    _plot_and_save(monitor, results_dir="results")
    return monitor


def run_benchmark(num_iterations: int = 100) -> PerformanceMonitor:
    _print_header()

    monitor = PerformanceMonitor()
    gs = GroundStation(node_id=1000)

    network_gs = SimulatedNetwork(NetworkConfig(delay_ms=5.0, jitter_ms=0.0, seed=4, real_time=False))
    network_peer = SimulatedNetwork(NetworkConfig(delay_ms=1.0, jitter_ms=0.0, seed=5, real_time=False))

    # Enroll all UAVs up front so provisioning can be saved once.
    uav = UAV(node_id=1, puf_seed=42)
    uav_a = UAV(node_id=2, puf_seed=100)
    uav_b = UAV(node_id=3, puf_seed=101)
    gs.enroll_uav(uav, num_crps=max(DEFAULT_NUM_CRPS, num_iterations + 5))
    gs.enroll_uav(uav_a, num_crps=DEFAULT_NUM_CRPS)
    gs.enroll_uav(uav_b, num_crps=DEFAULT_NUM_CRPS)

    _save_provisioning(gs, [uav, uav_a, uav_b], out_dir="provisioning")

    print(f"[Benchmark] Phase 2: {num_iterations} authentications")
    for _ in range(num_iterations):
        m2 = uav.phase2_authenticate_with_gs(gs, network_gs)
        monitor.record_phase2(m2)
        if not m2.success:
            # Stop early if CRPs are exhausted or BCH starts failing.
            break

    m2a = uav_a.phase2_authenticate_with_gs(gs, network_gs)
    m2b = uav_b.phase2_authenticate_with_gs(gs, network_gs)
    monitor.record_phase2(m2a)
    monitor.record_phase2(m2b)

    if m2a.success and m2b.success:
        gs.build_peer_credentials([uav_a, uav_b])
        print(f"\n[Benchmark] Phase 3: {num_iterations} peer authentications")
        for _ in range(num_iterations):
            m3 = uav_a.phase3_authenticate_with_peer(uav_b, network_peer)
            monitor.record_phase3(m3)
            if not m3.success:
                break

    print()
    print(monitor.report_text())
    export_report(monitor, results_dir="results")
    _plot_and_save(monitor, results_dir="results")
    return monitor
