"""Ground Station TCP server (two-laptop demo).

This server expects a pre-provisioned GS state JSON created by `provision.py`.
It handles Phase-2 authentication over a simple newline-delimited JSON protocol.

Run:
  python ground_station_server.py --db provisioning/gs_state.json --host 0.0.0.0 --port 5000
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
from typing import Any

from uav_puf_auth.storage import load_gs_state, save_gs_state


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
            raise ConnectionError("Client disconnected")
        if chunk == b"\n":
            break
        buf.extend(chunk)
        if len(buf) > 1024 * 1024:
            raise ValueError("Message too large")
    return json.loads(buf.decode("utf-8"))


def handle_client(sock: socket.socket, gs, gs_db_path: str, persist: bool) -> None:
    try:
        msg1 = _recv_line(sock)
        if msg1.get("type") != "phase2_msg1":
            _send_line(sock, {"type": "error", "message": "Expected phase2_msg1"})
            return

        tid = _b64d(msg1["tid"])
        ts1 = int(msg1["ts1"])
        nonce_u = _b64d(msg1["nonce_u"])
        eta1 = _b64d(msg1["eta1"])

        try:
            challenge, gs_nonce, eta2, ts2 = gs.phase2_msg1(tid, ts1, nonce_u, eta1)
        except Exception as e:
            _send_line(sock, {"type": "error", "message": f"msg1 rejected: {e}"})
            return

        _send_line(
            sock,
            {
                "type": "phase2_msg2",
                "challenge": _b64e(challenge),
                "gs_nonce": _b64e(gs_nonce),
                "eta2": _b64e(eta2),
                "ts2": ts2,
            },
        )

        try:
            msg3 = _recv_line(sock)
        except ConnectionError:
            # Client may disconnect if it encountered a local error.
            print("[GS] Client disconnected before msg3")
            return
        if msg3.get("type") != "phase2_msg3":
            _send_line(sock, {"type": "error", "message": "Expected phase2_msg3"})
            return

        uav_id = int(msg3["uav_id"])
        masked_response = _b64d(msg3["masked_response"])
        eta3 = _b64d(msg3["eta3"])
        nonce2 = _b64d(msg3["nonce2"])
        ts3 = int(msg3["ts3"])

        try:
            enc_payload, eta4, ts4 = gs.phase2_msg3(uav_id, masked_response, eta3, nonce2, ts3)
        except Exception as e:
            _send_line(sock, {"type": "error", "message": f"msg3 rejected: {e}"})
            return

        _send_line(
            sock,
            {
                "type": "phase2_msg4",
                "enc_payload": _b64e(enc_payload),
                "eta4": _b64e(eta4),
                "ts4": ts4,
            },
        )

        if persist:
            save_gs_state(gs, gs_db_path)

    except ConnectionError as e:
        print(f"[GS] Client connection error: {e}")
    except Exception as e:
        # Keep the server running even if one client misbehaves.
        print(f"[GS] Error handling client: {e}")

    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> None:
    p = argparse.ArgumentParser(description="Ground Station server (Phase 2)")
    p.add_argument("--db", required=True, help="Path to gs_state.json (created by provision.py)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument(
        "--persist",
        action="store_true",
        help="Write updated GS state back to --db (consumed CRPs, rotated TIDs)",
    )
    args = p.parse_args()

    gs = load_gs_state(args.db)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(5)

    print(f"[GS] Listening on {args.host}:{args.port}")
    print(f"[GS] DB: {args.db}")

    while True:
        client, addr = server.accept()
        print(f"[GS] Connection from {addr}")
        try:
            handle_client(client, gs, gs_db_path=args.db, persist=args.persist)
        except Exception as e:
            # Extra safety: never crash the accept loop.
            print(f"[GS] Unhandled client error: {e}")


if __name__ == "__main__":
    main()
