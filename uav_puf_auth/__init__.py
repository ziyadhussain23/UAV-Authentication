"""PUF-Based UAV Authentication Protocol Simulator (Python standalone).

This package contains a modular implementation of the four-phase protocol
architecture described in the project PDFs.
"""

from .entities import GroundStation, UAV
from .export import export_report
from .network import NetworkConfig, SimulatedNetwork
from .performance import PerformanceMonitor
from .simulations import run_benchmark, run_single_authentication_test, run_swarm_authentication_test

__all__ = [
    "GroundStation",
    "UAV",
    "NetworkConfig",
    "SimulatedNetwork",
    "PerformanceMonitor",
    "export_report",
    "run_single_authentication_test",
    "run_swarm_authentication_test",
    "run_benchmark",
]
