"""Project-wide constants for the PUF-based UAV authentication simulator."""

from __future__ import annotations

CHALLENGE_BITS = 128
CHALLENGE_BYTES = CHALLENGE_BITS // 8

# We model a 128-bit response by evaluating the 1-bit ArbiterPUF 128 times
# using sub-challenges deterministically derived from the 128-bit seed.
RESPONSE_BITS = 128
RESPONSE_BYTES = RESPONSE_BITS // 8

HASH_BITS = 160
HASH_BYTES = HASH_BITS // 8

UAV_ID_BYTES = 8  # 64-bit
TID_BYTES = 8  # 64-bit temporary identity

TS_BYTES = 4  # 32-bit timestamp

PHASE2_NONCE_BYTES = 16  # 128-bit
PHASE3_NONCE_BYTES = 20  # 160-bit (matches paper message sizes)

DEFAULT_PUF_NOISE = 0.03
DEFAULT_NUM_CRPS = 12

# Simple freshness check for timestamps.
TIMESTAMP_WINDOW_S = 2

# Network simulation defaults.
DEFAULT_LINK_DELAY_MS = 5.0
DEFAULT_LINK_JITTER_MS = 0.0
