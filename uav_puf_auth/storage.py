"""JSON (de)serialization helpers for two-laptop demos.

This lets you provision UAVs + GS in a secure environment once, then copy
state files to separate laptops for socket-based Phase-2 authentication.

All bytes are stored as base64 strings.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from .entities import GroundStation, UAV, _GSRecord  # type: ignore
from .models import CRPEntry


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def save_gs_state(gs: GroundStation, path: str | Path) -> Path:
    path = Path(path)

    records = []
    for rec in gs._records.values():  # noqa: SLF001 (intentional for serialization)
        records.append(
            {
                "uav_id": rec.uav_id,
                "tid": _b64e(rec.tid),
                "tau": _b64e(rec.tau),
                "registered_at": rec.registered_at,
                "crps": [
                    {
                        "challenge": _b64e(c.challenge),
                        "helper_data": _b64e(c.helper_data),
                        "response_hash": _b64e(c.response_hash),
                        "consumed": bool(c.consumed),
                    }
                    for c in rec.crps
                ],
            }
        )

    data = {
        "node_id": gs.node_id,
        "network_nonce": _b64e(gs.network_nonce),
        "records": records,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return path


def load_gs_state(path: str | Path) -> GroundStation:
    path = Path(path)
    data = json.loads(path.read_text())

    gs = GroundStation(node_id=int(data.get("node_id", 1000)))
    gs.network_nonce = _b64d(data["network_nonce"])

    gs._records.clear()  # noqa: SLF001
    gs._tid_to_id.clear()  # noqa: SLF001

    for r in data["records"]:
        crps = [
            CRPEntry(
                challenge=_b64d(c["challenge"]),
                helper_data=_b64d(c["helper_data"]),
                response_hash=_b64d(c["response_hash"]),
                consumed=bool(c.get("consumed", False)),
            )
            for c in r["crps"]
        ]
        rec = _GSRecord(
            uav_id=int(r["uav_id"]),
            tid=_b64d(r["tid"]),
            tau=_b64d(r["tau"]),
            crps=crps,
            registered_at=int(r["registered_at"]),
        )
        gs._records[rec.uav_id] = rec  # noqa: SLF001
        gs._tid_to_id[rec.tid] = rec.uav_id  # noqa: SLF001

    return gs


def save_uav_state(uav: UAV, path: str | Path) -> Path:
    path = Path(path)

    helper = { _b64e(ch): _b64e(hd) for ch, hd in uav._helper_data.items() }  # noqa: SLF001

    data = {
        "node_id": uav.node_id,
        "puf_seed": int(uav.puf.config.seed),
        "puf_noisiness": float(uav.puf.config.noisiness),
        "tid": _b64e(uav.tid),
        "tau": _b64e(uav.tau),
        "helper_data": helper,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return path


def load_uav_state(path: str | Path) -> UAV:
    path = Path(path)
    data = json.loads(path.read_text())

    uav = UAV(
        node_id=int(data["node_id"]),
        puf_seed=int(data["puf_seed"]),
        noise_level=float(data.get("puf_noisiness", 0.03)),
    )

    helper_map = { _b64d(k): _b64d(v) for k, v in data["helper_data"].items() }
    uav.install_enrollment(tid=_b64d(data["tid"]), tau=_b64d(data["tau"]), helper_data=helper_map)
    return uav
