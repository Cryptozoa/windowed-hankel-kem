"""Canonical 12-bit packing and pure Python 4-PAM message encoding."""

import numpy as np

from .params import PAM_POINTS, Q_MASK, W


def pack_12bit(arr: np.ndarray) -> bytes:
    """Pack pairs of coefficients in [0, 4095] into three bytes."""
    flat = np.asarray(arr).flatten()
    n = len(flat)
    if n % 2 != 0:
        raise ValueError(f"Array length must be even for 12-bit packing, got {n}")
    if np.any((flat < 0) | (flat > Q_MASK)):
        raise ValueError("Value out of range for 12-bit packing (>= 4096 or < 0)")

    flat = flat.astype(np.uint16)
    x0 = flat[0::2]
    x1 = flat[1::2]

    out = np.empty((n // 2, 3), dtype=np.uint8)
    out[:, 0] = (x0 & 0xFF).astype(np.uint8)
    out[:, 1] = (((x0 >> 8) & 0x0F) | ((x1 & 0x0F) << 4)).astype(np.uint8)
    out[:, 2] = ((x1 >> 4) & 0xFF).astype(np.uint8)
    return out.tobytes()


def unpack_12bit(buf: bytes, count: int) -> np.ndarray:
    """Unpack exactly count coefficients from the existing 12-bit layout."""
    if count % 2 != 0:
        raise ValueError(f"Count must be even for 12-bit unpacking, got {count}")
    expected_bytes = (count * 3) // 2
    if len(buf) != expected_bytes:
        raise ValueError(f"12-bit buffer length mismatch: expected {expected_bytes}, got {len(buf)}")

    raw = np.frombuffer(buf, dtype=np.uint8).reshape((count // 2, 3))
    b0 = raw[:, 0].astype(np.int64)
    b1 = raw[:, 1].astype(np.int64)
    b2 = raw[:, 2].astype(np.int64)

    x0 = b0 | ((b1 & 0x0F) << 8)
    x1 = (b1 >> 4) | (b2 << 4)

    out = np.empty(count, dtype=np.int64)
    out[0::2] = x0
    out[1::2] = x1
    return out


def encode_message_4pam_256(m_bytes: bytes, window_size: int = W) -> np.ndarray:
    """Encode each low-to-high two-bit symbol using the existing constellation."""
    if len(m_bytes) != 32:
        raise ValueError(f"Shared secret message must be exactly 32 bytes, got {len(m_bytes)}")
    if window_size != 128:
        raise ValueError(f"Window size must be 128 for 256-bit message, got {window_size}")

    symbols = []
    for byte in m_bytes:
        symbols.append(byte & 0x03)
        symbols.append((byte >> 2) & 0x03)
        symbols.append((byte >> 4) & 0x03)
        symbols.append((byte >> 6) & 0x03)

    sym_arr = np.array(symbols, dtype=np.int64)
    return PAM_POINTS[sym_arr]


def decode_message_4pam_256(noisy_vector: np.ndarray, window_size: int = W) -> bytes:
    """Pure Python reference decoder with the existing [-512, 511] cells."""
    if len(noisy_vector) != window_size:
        raise ValueError(f"Input vector length mismatch: expected {window_size}, got {len(noisy_vector)}")

    w_arr = noisy_vector.astype(np.int64)
    recovered_syms = (((w_arr + 512) & Q_MASK) >> 10).astype(np.uint8)

    out_bytes = bytearray(32)
    for byte_idx in range(32):
        s0 = int(recovered_syms[byte_idx * 4 + 0])
        s1 = int(recovered_syms[byte_idx * 4 + 1])
        s2 = int(recovered_syms[byte_idx * 4 + 2])
        s3 = int(recovered_syms[byte_idx * 4 + 3])
        out_bytes[byte_idx] = s0 | (s1 << 2) | (s2 << 4) | (s3 << 6)

    return bytes(out_bytes)
