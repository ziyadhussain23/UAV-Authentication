"""Module entrypoint.

Allows:
  python -m uav_puf_auth
  python -m uav_puf_auth --mode swarm --num-uavs 5
"""

from __future__ import annotations

import argparse

from .simulations import run_benchmark, run_single_authentication_test, run_swarm_authentication_test


def main() -> None:
    parser = argparse.ArgumentParser(description="PUF-based UAV authentication simulator")
    parser.add_argument(
        "--mode",
        choices=["single", "swarm", "benchmark"],
        default="single",
        help="Which simulation to run",
    )
    parser.add_argument("--num-uavs", type=int, default=5, help="UAV count for swarm mode")
    parser.add_argument("--iterations", type=int, default=100, help="Iteration count for benchmark mode")
    args = parser.parse_args()

    if args.mode == "single":
        run_single_authentication_test()
    elif args.mode == "swarm":
        run_swarm_authentication_test(num_uavs=args.num_uavs)
    elif args.mode == "benchmark":
        run_benchmark(num_iterations=args.iterations)


if __name__ == "__main__":
    main()
