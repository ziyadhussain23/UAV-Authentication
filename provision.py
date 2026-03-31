"""Secure provisioning step (Phase 1 enrollment) for two-laptop demos.

Run this once in a secure environment. It will:
- create a Ground Station + UAV(s)
- perform enrollment (CRP generation + helper data)
- write JSON state files you can copy to different laptops

Example:
  python provision.py --num-uavs 1 --out-dir provisioning
"""

from __future__ import annotations

import argparse
from pathlib import Path

from uav_puf_auth.entities import GroundStation, UAV
from uav_puf_auth.storage import save_gs_state, save_uav_state


def main() -> None:
    p = argparse.ArgumentParser(description="Provision GS/UAV state for socket demo")
    p.add_argument("--num-uavs", type=int, default=1)
    p.add_argument("--out-dir", type=str, default="provisioning")
    p.add_argument("--num-crps", type=int, default=12)
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    gs = GroundStation(node_id=1000)

    uavs: list[UAV] = []
    for i in range(args.num_uavs):
        uav = UAV(node_id=i + 1, puf_seed=100 + i)
        gs.enroll_uav(uav, num_crps=args.num_crps)
        uavs.append(uav)

    gs_path = save_gs_state(gs, out_dir / "gs_state.json")
    print(f"[OK] Wrote {gs_path}")

    for uav in uavs:
        uav_path = save_uav_state(uav, out_dir / f"uav_{uav.node_id}.json")
        print(f"[OK] Wrote {uav_path}")


if __name__ == "__main__":
    main()
