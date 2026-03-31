"""Plotting utilities (latency distributions, scalability curves)."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def plot_latency_histogram(
    phase2_latencies_ms: list[float],
    phase3_latencies_ms: list[float],
    out_path: str | Path = "visualization/latency_distribution.png",
    show: bool = False,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    if phase2_latencies_ms:
        ax1.hist(phase2_latencies_ms, bins=20, alpha=0.7, edgecolor="black")
        ax1.axvline(
            np.mean(phase2_latencies_ms),
            color="red",
            linestyle="--",
            label=f"Mean: {np.mean(phase2_latencies_ms):.2f} ms",
        )
    ax1.set_xlabel("Latency (ms)")
    ax1.set_ylabel("Frequency")
    ax1.set_title("Phase 2: UAV↔GS Authentication")
    if phase2_latencies_ms:
        ax1.legend()

    if phase3_latencies_ms:
        ax2.hist(phase3_latencies_ms, bins=20, alpha=0.7, edgecolor="black")
        ax2.axvline(
            np.mean(phase3_latencies_ms),
            color="red",
            linestyle="--",
            label=f"Mean: {np.mean(phase3_latencies_ms):.2f} ms",
        )
    ax2.set_xlabel("Latency (ms)")
    ax2.set_ylabel("Frequency")
    ax2.set_title("Phase 3: UAV↔UAV Peer Auth")
    if phase3_latencies_ms:
        ax2.legend()

    plt.tight_layout()
    fig.savefig(out_path, dpi=300)
    if show:
        plt.show()
    plt.close(fig)
    return out_path


def plot_scalability(
    num_uavs: list[int],
    phase2_avg_latency_ms: list[float],
    out_path: str | Path = "visualization/scalability.png",
    show: bool = False,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fig = plt.figure(figsize=(10, 6))
    plt.plot(num_uavs, phase2_avg_latency_ms, "o-", linewidth=2, markersize=6)
    plt.xlabel("Number of UAVs")
    plt.ylabel("Average Phase 2 Latency (ms)")
    plt.title("Protocol Scalability")
    plt.grid(alpha=0.3)
    fig.savefig(out_path, dpi=300)
    if show:
        plt.show()
    plt.close(fig)
    return out_path


def plot_compute_vs_network_breakdown(
    phase2_compute_ms: list[float],
    phase2_net_ms: list[float],
    phase3_compute_ms: list[float],
    phase3_net_ms: list[float],
    out_path: str | Path = "visualization/compute_vs_network.png",
    show: bool = False,
) -> Path:
    """Stacked bar chart: mean compute vs mean network per phase."""

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    p2_comp = float(np.mean(phase2_compute_ms)) if phase2_compute_ms else 0.0
    p2_net = float(np.mean(phase2_net_ms)) if phase2_net_ms else 0.0
    p3_comp = float(np.mean(phase3_compute_ms)) if phase3_compute_ms else 0.0
    p3_net = float(np.mean(phase3_net_ms)) if phase3_net_ms else 0.0

    labels = ["Phase 2 (UAV↔GS)", "Phase 3 (UAV↔UAV)"]
    comp = np.array([p2_comp, p3_comp], dtype=float)
    net = np.array([p2_net, p3_net], dtype=float)

    fig = plt.figure(figsize=(10, 5))
    plt.bar(labels, comp, label="Compute (ms)")
    plt.bar(labels, net, bottom=comp, label="Network (ms)")
    plt.ylabel("Mean time (ms)")
    plt.title("Mean Latency Breakdown (Compute vs Network)")
    plt.legend()
    plt.tight_layout()

    fig.savefig(out_path, dpi=300)
    if show:
        plt.show()
    plt.close(fig)
    return out_path
