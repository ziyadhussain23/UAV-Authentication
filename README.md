# PUF-Based UAV Authentication Protocol (Python Simulation)

**Project:** IIITG Final Year Project (March 2026)  
**Goal:** Simulate the *PUF-based UAV authentication protocol* (4-phase architecture) and measure:

- Phase 2 latency + overhead (UAV ↔ Ground Station)
- Phase 3 latency + overhead (UAV ↔ UAV peer authentication)
- Success rate across iterations

This implementation is **modular** (not a single file) and is aligned with the PDFs in this repo:

- `PUF-Based UAV Authentication Protocol  Complete Four-Phase Architecture.pdf`
- `PUF Based UAV Authentication.pdf`

---

## What Technology Is Used? (Paper ↔ Code Mapping)

### 1) PUF Type

**Paper:** Strong PUF (examples: Arbiter PUF / RO-PUF)  
**Code:** **Arbiter PUF** simulated using `pypuf`.

- Implementation: `pypuf.simulation.ArbiterPUF`
- Challenge size: **128-bit** (16 bytes)
- Response size: **128-bit** (16 bytes)

**Important detail:** `pypuf` ArbiterPUF outputs **1 bit** per evaluation. To obtain a 128-bit response (as used in the protocol), we deterministically derive 128 sub-challenges from the 128-bit seed challenge and evaluate the 1-bit PUF 128 times.

Where in code:

- `uav_puf_auth/puf.py`

### 2) Error Correction (Helper Data)

**Paper:** BCH error correction (helper data is public).  
**Code:** BCH via `bchlib`.

- Configuration: polynomial **8219**, strength **t = 18** (correct up to 18 bit errors)
- Helper data: `ecc = bch.encode(response_ref)`
- Reproduction: `nerr = bch.decode(data, ecc)` then `bch.correct(data, ecc)`

Where in code:

- `uav_puf_auth/fuzzy.py`

### 3) Lightweight Hash (SPONGENT-160)

**Paper:** SPONGENT-160 (160-bit output)  
**Code:** **SHA3-256 truncated to 160 bits** (20 bytes).

We do this because SPONGENT isn’t commonly available in standard Python crypto libraries.
For your report, you can describe this as:

> “SPONGENT-160 substituted by SHA3-256 truncated to 160 bits to preserve output length and message-size accounting.”

Where in code:

- `uav_puf_auth/crypto.py` → `hash160()`

### 4) MAC and Encryption (for puzzles / confirmation)

**Paper:** `MAC_K(M)` and `Enc_K(M)`  
**Code (simulation-friendly):**

- MAC: `mac160(key, msg) = hash160(key || msg)`
- Encryption: **hash-derived stream XOR** using SHAKE256 (`stream_xor()`)

These are lightweight placeholders to keep the protocol structure + message lengths consistent.
If you need “production crypto” later, replace them with AES-GCM / ChaCha20-Poly1305.

Where in code:

- `uav_puf_auth/crypto.py` → `mac160()`, `stream_xor()`

### 5) Communication Technology / Delay

**Standalone simulation:** we use a simple *delay model* (not real Wi‑Fi)

- Fixed one-way delay + optional jitter in `SimulatedNetwork`
- You can tune it to approximate:
	- Wi‑Fi (1–5 ms one-way)
	- LoRa (100–500 ms one-way)

**Two-laptop demo:** real network using **TCP sockets**

- GS server: `ground_station_server.py`
- UAV client: `uav_client.py`

Where in code:

- `uav_puf_auth/network.py`

---

## Protocol Phases Implemented

### Phase 1 — Enrollment / Registration

- GS generates CRPs (challenges)
- UAV evaluates PUF and GS stores only a **hash** of the reference response
- GS generates **BCH helper data** for each CRP
- GS assigns:
	- permanent `ID_i`
	- temporary `TID_i` (rotated later)
	- registration token `τ_i`

In code: `GroundStation.enroll_uav()`

### Phase 2 — UAV ↔ Ground Station Authentication

- 4 messages (2 round-trips)
- CRP is consumed after successful authentication
- `TID` is rotated for anonymity
- GS establishes a session key with the UAV (used to protect the confirmation payload)

In code: `UAV.phase2_authenticate_with_gs()` and `GroundStation.phase2_msg1()/phase2_msg3()`

### Phase 3 — UAV ↔ UAV Peer Authentication

- 3 messages (1.5 round-trips)
- Requires peer credentials (masks + peer challenges) distributed after Phase 2
- This simulator runs **full-mesh** P2P authentication in swarm mode

In code: `UAV.phase3_authenticate_with_peer()` + `GroundStation.build_peer_credentials()`

### Phase 4 — Session Key Establishment

After successful Phase 3, both UAVs derive a shared session key.

In code we derive a basic session key at the end of Phase 3 (placeholder for Phase 4).

---

## Message Size Accounting (Matches Paper Targets)

### Phase 2 (Target: 1680 bits ≈ 210 bytes)

| Message | Direction | Bits (paper) | Bytes |
|--------:|-----------|--------------|------:|
| M1 | UAV → GS | 384 | 48 |
| M2 | GS → UAV | 448 | 56 |
| M3 | UAV → GS | 448 | 56 |
| M4 | GS → UAV | 400 | 50 |
| **Total** |  | **1680** | **210** |

### Phase 3 (Target: 1568 bits ≈ 196 bytes)

| Message | Direction | Bits (paper) | Bytes |
|--------:|-----------|--------------|------:|
| P1 | UAVi → UAVj | 544 | 68 |
| P2 | UAVj → UAVi | 512 | 64 |
| P3 | UAVi → UAVj | 512 | 64 |
| **Total** |  | **1568** | **196** |

---

## Setup (Latest Python + pip)

This repo uses a local virtual environment under `.venv/`.

Tested on this workspace with **Python 3.13.x**.

```bash
source .venv/bin/activate

python --version
python -m pip --version

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Dependencies

- `pypuf` — Arbiter PUF simulation
- `bchlib` — BCH error correction (helper data)
- `pycryptodome` — SHA3-256 and SHAKE256 used for `hash160()` + stream-XOR
- `numpy` — bit packing/unpacking for PUF responses
- `matplotlib` — optional plotting utilities
- `simpy` — installed for future event-driven simulation (current implementation uses a simple delay model in `uav_puf_auth/network.py`)

---

## Run (Standalone)

```bash
# Single UAV ↔ GS
python -m uav_puf_auth

# Swarm: Phase 2 for N UAVs + Phase 3 full mesh (all pairs)
python -m uav_puf_auth --mode swarm --num-uavs 5

# Benchmark
python -m uav_puf_auth --mode benchmark --iterations 100
```

---

## Output Files

- `results/phase2_results.csv` — each Phase 2 attempt with readable per-step columns
- `results/phase3_results.csv` — each Phase 3 pair attempt with readable per-step columns
- `results/overhead_report.txt` — summary (mean/stdev/min/max, success rate)

Plots (auto-generated on each run):

- `results/latency_distribution.png`
- `results/compute_vs_network.png`

To display plot windows (optional):

```bash
UAV_PUF_AUTH_SHOW_PLOTS=1 python -m uav_puf_auth --mode swarm --num-uavs 5
```

Provisioning (auto-generated on each run):

- `provisioning/gs_state.json`
- `provisioning/uav_<id>.json`

Console output also prints a *paper-style message-size accounting*, the configured network delay model, plus a per-message timing breakdown separating computation vs simulated network delay.

---

## Two-Laptop Demo (Optional)

### 1) Provision in secure environment (Phase 1)

```bash
python provision.py --num-uavs 1 --out-dir provisioning --num-crps 12
```

This creates:

- `provisioning/gs_state.json`
- `provisioning/uav_1.json`

### 2) Laptop 2 (Ground Station)

```bash
python ground_station_server.py --db provisioning/gs_state.json --host 0.0.0.0 --port 5000 --persist
```

### 3) Laptop 1 (UAV)

```bash
python uav_client.py --state provisioning/uav_1.json --host <GS_IP> --port 5000
```

---

## Code Map (Where To Edit)

- `uav_puf_auth/puf.py` — Arbiter PUF simulation + noise
- `uav_puf_auth/fuzzy.py` — BCH helper data + correction
- `uav_puf_auth/crypto.py` — hash160/MAC/stream XOR
- `uav_puf_auth/network.py` — delay model (Wi‑Fi / LoRa style)
- `uav_puf_auth/entities.py` — Phase 1/2/3 protocol logic
- `uav_puf_auth/simulations.py` — single/swarm/benchmark runners

---

## Notes / Limitations (For Your Report)

- This is a **software simulation** of PUF behavior. Hardware PUF timings will differ.
- SPONGENT-160 is replaced with SHA3-256 truncated to 160 bits to preserve output size.
- Encryption and MAC are lightweight placeholders to preserve protocol structure; use authenticated encryption (AEAD) if you want production-grade security.
- CRPs are consumed; if you run too many Phase 2 authentications you must enroll with more CRPs.
