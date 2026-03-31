"""Core protocol entities (UAV, GroundStation) and Phase 2/3 logic."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Final

from .constants import (
    CHALLENGE_BYTES,
    DEFAULT_NUM_CRPS,
    HASH_BYTES,
    PHASE2_NONCE_BYTES,
    PHASE3_NONCE_BYTES,
    RESPONSE_BYTES,
    TIMESTAMP_WINDOW_S,
    TID_BYTES,
    UAV_ID_BYTES,
)
from .crypto import (
    hash160,
    mac160,
    now_u32,
    rand_bytes,
    secure_eq,
    stream_xor,
    u32_to_bytes,
)
from .fuzzy import BCHConfig, BCHFuzzyExtractor
from .models import CRPEntry, PeerCredential, PhaseMetrics
from .network import SimulatedNetwork
from .puf import PUFConfig, PUFSimulator


def u64_to_bytes(value: int) -> bytes:
    return int(value).to_bytes(UAV_ID_BYTES, byteorder="big", signed=False)


@dataclass(slots=True)
class _GSRecord:
    uav_id: int
    tid: bytes
    tau: bytes
    crps: list[CRPEntry]
    registered_at: int


@dataclass(slots=True)
class _Phase2Pending:
    uav_id: int
    tid: bytes
    nonce_u: bytes
    ts1: int
    challenge: bytes
    ts2: int


@dataclass(slots=True)
class _SessionInfo:
    challenge: bytes
    response: bytes  # stored only in-memory for the active session
    session_key_gs: bytes
    gs_nonce: bytes


class GroundStation:
    def __init__(self, node_id: int = 1000, bch_config: BCHConfig = BCHConfig()):
        self.node_id: int = node_id
        self._bch = BCHFuzzyExtractor(bch_config)

        # Network-wide nonce used as N_gs in peer-auth computations (Phase 3).
        self.network_nonce: bytes = rand_bytes(PHASE2_NONCE_BYTES)

        self._records: dict[int, _GSRecord] = {}
        self._tid_to_id: dict[bytes, int] = {}
        self._pending: dict[int, _Phase2Pending] = {}
        self._sessions: dict[int, _SessionInfo] = {}

    def enroll_uav(self, uav: "UAV", num_crps: int = DEFAULT_NUM_CRPS) -> None:
        t_reg = now_u32()

        tid = rand_bytes(TID_BYTES)
        tau = hash160(u64_to_bytes(uav.node_id) + u32_to_bytes(t_reg))

        crps: list[CRPEntry] = []
        helper_map: dict[bytes, bytes] = {}

        for _ in range(num_crps):
            challenge = rand_bytes(CHALLENGE_BYTES)

            # Enrollment happens in a controlled environment; we use majority voting
            # to create a stable reference response.
            response_ref = uav.puf.evaluate_stable(challenge, samples=7)

            helper = self._bch.enroll(response_ref)
            digest = hash160(response_ref)

            crps.append(CRPEntry(challenge=challenge, helper_data=helper, response_hash=digest))
            helper_map[challenge] = helper

        self._records[uav.node_id] = _GSRecord(
            uav_id=uav.node_id,
            tid=tid,
            tau=tau,
            crps=crps,
            registered_at=t_reg,
        )
        self._tid_to_id[tid] = uav.node_id

        # UAV stores public helper data for its own CRPs (for local reconstruction).
        uav.install_enrollment(tid=tid, tau=tau, helper_data=helper_map)

    def get_record_by_tid(self, tid: bytes) -> _GSRecord | None:
        uav_id = self._tid_to_id.get(tid)
        if uav_id is None:
            return None
        return self._records.get(uav_id)

    def _select_unused_crp(self, uav_id: int) -> CRPEntry:
        rec = self._records[uav_id]
        for entry in rec.crps:
            if not entry.consumed:
                return entry
        raise RuntimeError(f"No unused CRPs left for UAV {uav_id}")

    def phase2_msg1(self, tid: bytes, ts1: int, nonce_u: bytes, eta1: bytes) -> tuple[bytes, bytes, bytes, int]:
        """Handle Phase 2 message 1 and produce message 2 fields."""

        if abs(now_u32() - ts1) > TIMESTAMP_WINDOW_S:
            raise ValueError("Stale timestamp (replay suspected)")

        rec = self.get_record_by_tid(tid)
        if rec is None:
            raise ValueError("Unknown TID")

        expected = mac160(rec.tau, tid + u32_to_bytes(ts1) + nonce_u)
        if not secure_eq(expected, eta1):
            raise ValueError("Bad authentication hash")

        crp = self._select_unused_crp(rec.uav_id)
        ts2 = now_u32()
        gs_nonce = self.network_nonce
        eta2 = mac160(rec.tau, crp.challenge + gs_nonce + nonce_u + u32_to_bytes(ts2))

        self._pending[rec.uav_id] = _Phase2Pending(
            uav_id=rec.uav_id,
            tid=tid,
            nonce_u=nonce_u,
            ts1=ts1,
            challenge=crp.challenge,
            ts2=ts2,
        )

        return crp.challenge, gs_nonce, eta2, ts2

    def phase2_msg3(
        self,
        uav_id: int,
        masked_response: bytes,
        eta3: bytes,
        nonce2: bytes,
        ts3: int,
    ) -> tuple[bytes, bytes, int]:
        """Handle Phase 2 message 3 and produce message 4 fields.

        Returns (enc_payload, eta4, ts4).
        """

        pending = self._pending.get(uav_id)
        if pending is None:
            raise ValueError("No pending Phase 2 context")
        if abs(now_u32() - ts3) > TIMESTAMP_WINDOW_S:
            raise ValueError("Stale timestamp")

        rec = self._records[uav_id]
        expected_eta3 = mac160(rec.tau, masked_response + nonce2 + u32_to_bytes(ts3))
        if not secure_eq(expected_eta3, eta3):
            raise ValueError("Bad response token")

        # Unmask and verify response hash.
        unmasked = stream_xor(
            key=rec.tau,
            plaintext_or_ciphertext=masked_response,
            info=pending.nonce_u + self.network_nonce + u32_to_bytes(ts3),
        )

        # Find CRP entry for this challenge.
        crp = next((c for c in rec.crps if c.challenge == pending.challenge), None)
        if crp is None:
            raise ValueError("CRP not found")

        if hash160(unmasked) != crp.response_hash:
            raise ValueError("PUF response mismatch")

        # Consume this CRP.
        crp.consumed = True

        # Derive session key with GS (for the encrypted confirmation payload).
        session_key = hash160(unmasked + pending.nonce_u + self.network_nonce + nonce2)
        self._sessions[uav_id] = _SessionInfo(
            challenge=pending.challenge,
            response=unmasked,
            session_key_gs=session_key,
            gs_nonce=self.network_nonce,
        )

        # Update TID for anonymity.
        ts4 = now_u32()
        new_tid = hash160(rec.tid + pending.nonce_u + self.network_nonce + u32_to_bytes(ts4))[:TID_BYTES]
        del self._tid_to_id[rec.tid]
        rec.tid = new_tid
        self._tid_to_id[new_tid] = uav_id

        # Build an encrypted confirmation payload sized to keep Phase-2 overhead
        # close to the paper's accounting (target total: 210 bytes).
        # plaintext payload = new_tid (8) || gs_nonce (16) || flags (2) = 26 bytes.
        flags: Final[bytes] = b"\x00\x01"
        plaintext = new_tid + self.network_nonce + flags
        enc_payload = stream_xor(session_key, plaintext, info=b"phase2-msg4")
        eta4 = mac160(session_key, enc_payload + u32_to_bytes(ts4))

        # Clear pending.
        del self._pending[uav_id]

        return enc_payload, eta4, ts4

    def get_session(self, uav_id: int) -> _SessionInfo | None:
        return self._sessions.get(uav_id)

    def build_peer_credentials(self, uavs: list["UAV"]) -> None:
        """Compute pairwise masks and install peer credentials on each UAV.

        This uses each UAV's active Phase-2 session response (in-memory only).
        """

        # Ensure all sessions exist.
        missing = [u.node_id for u in uavs if u.node_id not in self._sessions]
        if missing:
            raise RuntimeError(f"Missing Phase-2 sessions for UAVs: {missing}")

        for i, uav_i in enumerate(uavs):
            sess_i = self._sessions[uav_i.node_id]
            for uav_j in uavs[i + 1 :]:
                sess_j = self._sessions[uav_j.node_id]

                p_ij = hash160(sess_i.response + u64_to_bytes(uav_j.node_id) + self.network_nonce)
                p_ji = hash160(sess_j.response + u64_to_bytes(uav_i.node_id) + self.network_nonce)
                mask = bytes(a ^ b for a, b in zip(p_ij, p_ji, strict=True))

                uav_i.add_peer_credential(
                    PeerCredential(
                        peer_id=uav_j.node_id,
                        peer_tid=uav_j.tid,
                        peer_challenge=sess_j.challenge,
                        mask=mask,
                    )
                )
                uav_j.add_peer_credential(
                    PeerCredential(
                        peer_id=uav_i.node_id,
                        peer_tid=uav_i.tid,
                        peer_challenge=sess_i.challenge,
                        mask=mask,
                    )
                )


class UAV:
    def __init__(
        self,
        node_id: int,
        puf_seed: int,
        noise_level: float = 0.03,
        bch_config: BCHConfig = BCHConfig(),
    ):
        self.node_id: int = node_id
        self.puf = PUFSimulator(PUFConfig(seed=puf_seed, noisiness=noise_level))
        self._bch = BCHFuzzyExtractor(bch_config)

        # Provisioned in enrollment.
        self.tid: bytes = b""  # 64-bit
        self.tau: bytes = b""  # 160-bit registration token
        self._helper_data: dict[bytes, bytes] = {}

        # Populated in Phase 2.
        self.session_challenge: bytes = b""
        self.session_response: bytes = b""  # corrected, stable response (not transmitted)
        self.gs_nonce: bytes = b""
        self.session_key_gs: bytes = b""

        # Populated after Phase 2 credential distribution.
        self._peer_by_tid: dict[bytes, PeerCredential] = {}
        self._peer_by_id: dict[int, PeerCredential] = {}

    def install_enrollment(self, tid: bytes, tau: bytes, helper_data: dict[bytes, bytes]) -> None:
        self.tid = tid
        self.tau = tau
        self._helper_data = dict(helper_data)

    def add_peer_credential(self, cred: PeerCredential) -> None:
        self._peer_by_tid[cred.peer_tid] = cred
        self._peer_by_id[cred.peer_id] = cred

    def peer_credential_by_tid(self, tid: bytes) -> PeerCredential | None:
        return self._peer_by_tid.get(tid)

    def peer_credential_by_id(self, peer_id: int) -> PeerCredential | None:
        return self._peer_by_id.get(peer_id)

    def phase2_authenticate_with_gs(self, gs: GroundStation, network: SimulatedNetwork) -> PhaseMetrics:
        """Run Phase 2 (UAV↔GS) authentication."""

        start = time.perf_counter()
        overhead = 0
        net_delay_ms = 0.0
        step_ms: dict[str, float] = {}
        compute_accum_ms = 0.0

        bch_bitflips: int | None = None

        # ---------------- Message 1 (UAV -> GS) ----------------
        t0 = time.perf_counter()
        ts1 = now_u32()
        nonce_u = rand_bytes(PHASE2_NONCE_BYTES)
        eta1 = mac160(self.tau, self.tid + u32_to_bytes(ts1) + nonce_u)
        t1 = time.perf_counter()
        step_ms["m1_uav_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["m1_uav_compute_ms"]

        msg1_size = TID_BYTES + 4 + PHASE2_NONCE_BYTES + HASH_BYTES
        overhead += msg1_size
        d = network.transmit(msg1_size)
        step_ms["m1_net_ms"] = d
        net_delay_ms += d

        t0 = time.perf_counter()
        try:
            challenge, gs_nonce, eta2, ts2 = gs.phase2_msg1(self.tid, ts1, nonce_u, eta1)
        except Exception as e:
            t1 = time.perf_counter()
            step_ms["m1_gs_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["m1_gs_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details=f"Phase2 msg1 failed: {e}",
                step_ms=step_ms,
            )
        t1 = time.perf_counter()
        step_ms["m1_gs_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["m1_gs_compute_ms"]

        # ---------------- Message 2 (GS -> UAV) ----------------
        msg2_size = CHALLENGE_BYTES + PHASE2_NONCE_BYTES + HASH_BYTES + 4
        overhead += msg2_size
        d = network.transmit(msg2_size)
        step_ms["m2_net_ms"] = d
        net_delay_ms += d

        t0 = time.perf_counter()
        expected_eta2 = mac160(self.tau, challenge + gs_nonce + nonce_u + u32_to_bytes(ts2))
        ok = secure_eq(expected_eta2, eta2)
        t1 = time.perf_counter()
        step_ms["m2_uav_verify_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["m2_uav_verify_ms"]
        if not ok:
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="Bad GS MAC",
                step_ms=step_ms,
            )

        self.gs_nonce = gs_nonce
        self.session_challenge = challenge

        # ---------------- Message 3 (UAV -> GS) ----------------
        t_m3_start = time.perf_counter()

        t0 = time.perf_counter()
        noisy = self.puf.evaluate(challenge)
        t1 = time.perf_counter()
        step_ms["puf_eval_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["puf_eval_ms"]

        helper = self._helper_data.get(challenge)
        if helper is None:
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="Missing helper data",
                step_ms=step_ms,
            )

        t0 = time.perf_counter()
        try:
            corrected, bitflips = self._bch.reproduce(noisy, helper)
        except Exception as e:
            t1 = time.perf_counter()
            step_ms["bch_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["bch_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details=f"BCH failed: {e}",
                step_ms=step_ms,
            )
        t1 = time.perf_counter()
        step_ms["bch_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["bch_ms"]
        bch_bitflips = int(bitflips)

        self.session_response = corrected

        t0 = time.perf_counter()
        ts3 = now_u32()
        nonce2 = rand_bytes(PHASE2_NONCE_BYTES)
        masked_response = stream_xor(
            key=self.tau,
            plaintext_or_ciphertext=corrected,
            info=nonce_u + gs_nonce + u32_to_bytes(ts3),
        )
        eta3 = mac160(self.tau, masked_response + nonce2 + u32_to_bytes(ts3))
        t1 = time.perf_counter()
        step_ms["m3_crypto_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["m3_crypto_ms"]

        t_m3_end = time.perf_counter()
        step_ms["m3_uav_compute_ms"] = (t_m3_end - t_m3_start) * 1000.0

        msg3_size = RESPONSE_BYTES + HASH_BYTES + PHASE2_NONCE_BYTES + 4
        overhead += msg3_size
        d = network.transmit(msg3_size)
        step_ms["m3_net_ms"] = d
        net_delay_ms += d

        t0 = time.perf_counter()
        try:
            enc_payload, eta4, ts4 = gs.phase2_msg3(
                uav_id=self.node_id,
                masked_response=masked_response,
                eta3=eta3,
                nonce2=nonce2,
                ts3=ts3,
            )
        except Exception as e:
            t1 = time.perf_counter()
            step_ms["m3_gs_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["m3_gs_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details=f"Phase2 msg3 failed: {e}",
                step_ms=step_ms,
            )
        t1 = time.perf_counter()
        step_ms["m3_gs_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["m3_gs_compute_ms"]

        # ---------------- Message 4 (GS -> UAV) ----------------
        msg4_size = len(enc_payload) + HASH_BYTES + 4
        overhead += msg4_size
        d = network.transmit(msg4_size)
        step_ms["m4_net_ms"] = d
        net_delay_ms += d

        t0 = time.perf_counter()
        session_key = hash160(corrected + nonce_u + gs_nonce + nonce2)
        expected_eta4 = mac160(session_key, enc_payload + u32_to_bytes(ts4))
        if not secure_eq(expected_eta4, eta4):
            t1 = time.perf_counter()
            step_ms["m4_uav_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["m4_uav_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="Bad confirmation MAC",
                step_ms=step_ms,
            )

        plaintext = stream_xor(session_key, enc_payload, info=b"phase2-msg4")
        new_tid = plaintext[:TID_BYTES]
        self.tid = new_tid
        self.session_key_gs = session_key
        t1 = time.perf_counter()
        step_ms["m4_uav_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["m4_uav_compute_ms"]

        compute_ms = compute_accum_ms
        bitflip_str = "?" if bch_bitflips is None else str(bch_bitflips)
        details = f"OK; bch_bitflips={bitflip_str}"

        return PhaseMetrics(
            success=True,
            latency_ms=compute_ms + net_delay_ms,
            compute_ms=compute_ms,
            net_ms=net_delay_ms,
            overhead_bytes=overhead,
            details=details,
            step_ms=step_ms,
        )

    def phase3_authenticate_with_peer(self, peer: "UAV", network: SimulatedNetwork) -> PhaseMetrics:
        """Run Phase 3 mutual authentication with another UAV.

        This simulates the three-message peer protocol and records total
        communication overhead.
        """

        start = time.perf_counter()
        overhead = 0
        net_delay_ms = 0.0
        step_ms: dict[str, float] = {}
        compute_accum_ms = 0.0

        cred_ij = self.peer_credential_by_id(peer.node_id)
        if cred_ij is None:
            end = time.perf_counter()
            compute_ms = (end - start) * 1000.0
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms,
                compute_ms=compute_ms,
                net_ms=0.0,
                overhead_bytes=0,
                details="Missing peer credential",
                step_ms=step_ms,
            )

        # ---------------- P1: i -> j ----------------
        t0 = time.perf_counter()
        ts1 = now_u32()
        n_i = rand_bytes(PHASE3_NONCE_BYTES)
        c_j = cred_ij.peer_challenge

        p_ij = hash160(self.session_response + u64_to_bytes(peer.node_id) + self.gs_nonce)
        eta1 = mac160(p_ij, self.tid + c_j + n_i + u32_to_bytes(ts1))
        t1 = time.perf_counter()
        step_ms["p1_i_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["p1_i_compute_ms"]

        p1_size = TID_BYTES + CHALLENGE_BYTES + PHASE3_NONCE_BYTES + HASH_BYTES + 4
        overhead += p1_size
        d = network.transmit(p1_size)
        step_ms["p1_net_ms"] = d
        net_delay_ms += d

        # Receiver side (peer)
        cred_ji = peer.peer_credential_by_tid(self.tid)
        if cred_ji is None:
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="Peer missing credential",
                step_ms=step_ms,
            )

        t0 = time.perf_counter()
        p_ji = hash160(peer.session_response + u64_to_bytes(self.node_id) + peer.gs_nonce)
        p_ij_from_peer = bytes(a ^ b for a, b in zip(cred_ji.mask, p_ji, strict=True))

        expected_eta1 = mac160(p_ij_from_peer, self.tid + c_j + n_i + u32_to_bytes(ts1))
        if not secure_eq(expected_eta1, eta1):
            t1 = time.perf_counter()
            step_ms["p1_p2_j_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["p1_p2_j_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="P1 MAC failed",
                step_ms=step_ms,
            )

        # ---------------- P2: j -> i ----------------
        ts2 = now_u32()
        n_j = rand_bytes(PHASE3_NONCE_BYTES)
        c_i = cred_ji.peer_challenge

        plaintext2 = n_j + c_i + u32_to_bytes(ts1)
        q_i = stream_xor(p_ij_from_peer, plaintext2, info=b"phase3-p2")
        eta2 = mac160(p_ij_from_peer, q_i + u32_to_bytes(ts2))
        t1 = time.perf_counter()
        step_ms["p1_p2_j_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["p1_p2_j_compute_ms"]

        p2_size = len(q_i) + HASH_BYTES + 4
        overhead += p2_size
        d = network.transmit(p2_size)
        step_ms["p2_net_ms"] = d
        net_delay_ms += d

        # i receives
        t0 = time.perf_counter()
        expected_eta2 = mac160(p_ij, q_i + u32_to_bytes(ts2))
        if not secure_eq(expected_eta2, eta2):
            t1 = time.perf_counter()
            step_ms["p2_p3_i_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["p2_p3_i_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="P2 MAC failed",
                step_ms=step_ms,
            )

        dec2 = stream_xor(p_ij, q_i, info=b"phase3-p2")
        n_j_dec = dec2[:PHASE3_NONCE_BYTES]
        c_i_dec = dec2[PHASE3_NONCE_BYTES : PHASE3_NONCE_BYTES + CHALLENGE_BYTES]
        ts1_dec = dec2[-4:]
        if n_j_dec != n_j or c_i_dec != self.session_challenge or ts1_dec != u32_to_bytes(ts1):
            t1 = time.perf_counter()
            step_ms["p2_p3_i_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["p2_p3_i_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="P2 decrypt/parse failed",
                step_ms=step_ms,
            )

        p_ji_from_mask = bytes(a ^ b for a, b in zip(cred_ij.mask, p_ij, strict=True))

        # ---------------- P3: i -> j ----------------
        ts3 = now_u32()
        n_i2 = rand_bytes(PHASE3_NONCE_BYTES)

        plaintext3 = n_i2 + c_j + u32_to_bytes(ts2)
        q_j = stream_xor(p_ji_from_mask, plaintext3, info=b"phase3-p3")
        eta3 = mac160(p_ji_from_mask, q_j + u32_to_bytes(ts3))
        t1 = time.perf_counter()
        step_ms["p2_p3_i_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["p2_p3_i_compute_ms"]

        p3_size = len(q_j) + HASH_BYTES + 4
        overhead += p3_size
        d = network.transmit(p3_size)
        step_ms["p3_net_ms"] = d
        net_delay_ms += d

        # peer receives
        t0 = time.perf_counter()
        expected_eta3 = mac160(p_ji, q_j + u32_to_bytes(ts3))
        if not secure_eq(expected_eta3, eta3):
            t1 = time.perf_counter()
            step_ms["p3_j_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["p3_j_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="P3 MAC failed",
                step_ms=step_ms,
            )

        dec3 = stream_xor(p_ji, q_j, info=b"phase3-p3")
        c_j_dec = dec3[PHASE3_NONCE_BYTES : PHASE3_NONCE_BYTES + CHALLENGE_BYTES]
        ts2_dec = dec3[-4:]
        if c_j_dec != peer.session_challenge or ts2_dec != u32_to_bytes(ts2):
            t1 = time.perf_counter()
            step_ms["p3_j_compute_ms"] = (t1 - t0) * 1000.0
            compute_accum_ms += step_ms["p3_j_compute_ms"]
            compute_ms = compute_accum_ms
            return PhaseMetrics(
                success=False,
                latency_ms=compute_ms + net_delay_ms,
                compute_ms=compute_ms,
                net_ms=net_delay_ms,
                overhead_bytes=overhead,
                details="P3 decrypt/parse failed",
                step_ms=step_ms,
            )

        # Phase 4 (basic session key) - computed but not used further in this simulation.
        _session_key_peer = hash160(n_i + n_j + p_ij + p_ji)

        t1 = time.perf_counter()
        step_ms["p3_j_compute_ms"] = (t1 - t0) * 1000.0
        compute_accum_ms += step_ms["p3_j_compute_ms"]

        compute_ms = compute_accum_ms
        return PhaseMetrics(
            success=True,
            latency_ms=compute_ms + net_delay_ms,
            compute_ms=compute_ms,
            net_ms=net_delay_ms,
            overhead_bytes=overhead,
            details="OK",
            step_ms=step_ms,
        )
