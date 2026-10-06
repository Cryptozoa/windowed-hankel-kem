"""Public sequence expansion and the existing CBD_2 byte sampler."""

import hashlib

import numpy as np

from .params import Q_MASK, TOTAL_A_LEN


def expand_public_sequence_a(seed: bytes, length: int = TOTAL_A_LEN) -> np.ndarray:
    """Expand SHAKE-256 words with the existing little-endian 12-bit mask."""
    shake = hashlib.shake_256(seed)
    raw = shake.digest(length * 2)
    arr = np.frombuffer(raw, dtype="<u2")
    return (arr[:length] & Q_MASK).astype(np.int64)


def sample_cbd2_from_bytes(raw_bytes: bytes, count: int) -> np.ndarray:
    """Sample CBD_2 from the lowest four bits of each input byte."""
    assert len(raw_bytes) >= count, f"CBD buffer underflow: need {count} bytes, got {len(raw_bytes)}"
    raw = np.frombuffer(raw_bytes[:count], dtype=np.uint8)

    raw_int = raw.astype(np.int64)
    a0 = (raw_int >> 0) & 1
    a1 = (raw_int >> 1) & 1
    b0 = (raw_int >> 2) & 1
    b1 = (raw_int >> 3) & 1

    return (a0 + a1) - (b0 + b1)
