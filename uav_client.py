"""UAV TCP client (two-laptop demo).

This client expects a pre-provisioned UAV state JSON created by `provision.py`.
It runs Phase-2 authentication against a GS server.

Run:
  python uav_client.py --state provisioning/uav_1.json --host 192.168.1.20 --port 5000
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import time
from typing import Any

from uav_puf_auth.constants import HASH_BYTES, PHASE2_NONCE_BYTES, RESPONSE_BYTES, TID_BYTES
from uav_puf_auth.crypto import (
    hash160,
    mac160,
    now_u32,
    rand_bytes,
    secure_eq,
    stream_xor,
    u32_to_bytes,
)
from uav_puf_auth.storage import load_uav_state, save_uav_state


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _send_line(sock: socket.socket, obj: dict[str, Any]) -> None:
    data = (json.dumps(obj) + "\n").encode("utf-8")
    sock.sendall(data)


def _recv_line(sock: socket.socket) -> dict[str, Any]:
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Server disconnected")
        if chunk == b"\n":
            break
        buf.extend(chunk)
        if len(buf) > 1024 * 1024:
            raise ValueError("Message too large")
    return json.loads(buf.decode("utf-8"))


def main() -> None:
    p = argparse.ArgumentParser(description="UAV client (Phase 2)")
    p.add_argument("--state", required=True, help="Path to uav_*.json (created by provision.py)")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=5000)
    p.add_argument(
        "--persist",
        action="store_true",
        help="Write updated UAV state back to --state (rotated TID)",
    )
    args = p.parse_args()

    uav = load_uav_state(args.state)

    # Measure end-to-end latency (real network + processing).
    start = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))

    # ---------------- Message 1 ----------------
    ts1 = now_u32()
    nonce_u = rand_bytes(PHASE2_NONCE_BYTES)
    eta1 = mac160(uav.tau, uav.tid + u32_to_bytes(ts1) + nonce_u)

    _send_line(
        sock,
        {
            "type": "phase2_msg1",
            "tid": _b64e(uav.tid),
            "ts1": ts1,
            "nonce_u": _b64e(nonce_u),
            "eta1": _b64e(eta1),
        },
    )

    msg2 = _recv_line(sock)
    if msg2.get("type") == "error":
        raise RuntimeError(msg2.get("message"))
    if msg2.get("type") != "phase2_msg2":
        raise RuntimeError("Unexpected response")

    challenge = _b64d(msg2["challenge"])
    gs_nonce = _b64d(msg2["gs_nonce"])
    eta2 = _b64d(msg2["eta2"])
    ts2 = int(msg2["ts2"])

    expected_eta2 = mac160(uav.tau, challenge + gs_nonce + nonce_u + u32_to_bytes(ts2))
    if not secure_eq(expected_eta2, eta2):
        raise RuntimeError("Bad GS MAC (msg2)")

    # ---------------- Message 3 ----------------
    noisy = uav.puf.evaluate(challenge)
    helper = uav._helper_data.get(challenge)  # noqa: SLF001 (state loaded from file)
    if helper is None:
        raise RuntimeError("Missing helper data for challenge")

    corrected, _ = uav._bch.reproduce(noisy, helper)  # noqa: SLF001

    ts3 = now_u32()
    nonce2 = rand_bytes(PHASE2_NONCE_BYTES)

    masked_response = stream_xor(
        key=uav.tau,
        plaintext_or_ciphertext=corrected,
        info=nonce_u + gs_nonce + u32_to_bytes(ts3),
    )
    eta3 = mac160(uav.tau, masked_response + nonce2 + u32_to_bytes(ts3))

    _send_line(
        sock,
        {
            "type": "phase2_msg3",
            "uav_id": uav.node_id,
            "masked_response": _b64e(masked_response),
            "eta3": _b64e(eta3),
            "nonce2": _b64e(nonce2),
            "ts3": ts3,
        },
    )

    msg4 = _recv_line(sock)
    if msg4.get("type") == "error":
        raise RuntimeError(msg4.get("message"))
    if msg4.get("type") != "phase2_msg4":
        raise RuntimeError("Unexpected response")

    enc_payload = _b64d(msg4["enc_payload"])
    eta4 = _b64d(msg4["eta4"])
    ts4 = int(msg4["ts4"])

    session_key = hash160(corrected + nonce_u + gs_nonce + nonce2)
    expected_eta4 = mac160(session_key, enc_payload + u32_to_bytes(ts4))
    if not secure_eq(expected_eta4, eta4):
        raise RuntimeError("Bad confirmation MAC (msg4)")

    plaintext = stream_xor(session_key, enc_payload, info=b"phase2-msg4")
    new_tid = plaintext[:TID_BYTES]
    uav.tid = new_tid

    if args.persist:
        save_uav_state(uav, args.state)

    sock.close()

    end = time.perf_counter()
    e2e_ms = (end - start) * 1000.0

    # Spec-style overhead (not JSON size):
    msg1_size = TID_BYTES + 4 + PHASE2_NONCE_BYTES + HASH_BYTES
    msg2_size = 16 + 16 + HASH_BYTES + 4
    msg3_size = RESPONSE_BYTES + HASH_BYTES + PHASE2_NONCE_BYTES + 4
    msg4_size = len(enc_payload) + HASH_BYTES + 4
    overhead = msg1_size + msg2_size + msg3_size + msg4_size

    print("✓ Authentication SUCCESSFUL!")
    print(f"  End-to-end latency: {e2e_ms:.2f} ms")
    print(f"  Protocol overhead (spec accounting): {overhead} bytes")


if __name__ == "__main__":
    main()
