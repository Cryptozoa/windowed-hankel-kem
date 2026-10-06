"""
Windowed Hankel LWE KEM: Core Cryptographic Engine
--------------------------------------------------
Academic Research Prototype implementing Aperiodic Windowed Hankel LWE.
Modulus: q = 4096 (2^12, Power-of-two, zero-rejection bitwise masking)
Lattice Dimension: n = 640
Window Size: W = 128 (128 coordinates x 2 bits = 256-bit message via 4-PAM)
Extended Dimension: m = n + W = 768
"""

import os
import math
import hashlib
from typing import Tuple, Optional
import numpy as np

# Canonical Mathematical Parameters
Q = 4096
Q_MASK = 0x0FFF
ETA = 2
N = 640
W = 128
M_LEN = N + W  # 768
TOTAL_A_LEN = 2 * N + W - 1  # 1407

# Constellation Parameters (4-PAM on Z_4096)
PAM_POINTS = np.array([0, 1024, 2048, 3072], dtype=np.int64)
DECISION_THRESHOLD = 512

# Optional native ARM64 NEON acceleration
import ctypes
_C_LIB = None
try:
    _lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libhankel_kem_neon.dylib")
    if os.path.exists(_lib_path):
        _C_LIB = ctypes.CDLL(_lib_path)
        _C_LIB.hankel_neon_forward_mul.argtypes = [
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_int16),
            ctypes.POINTER(ctypes.c_int16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_int,
            ctypes.c_int
        ]
        _C_LIB.hankel_neon_window_project.argtypes = [
            ctypes.POINTER(ctypes.c_int16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_int,
            ctypes.c_int
        ]
        _C_LIB.hankel_neon_decode_4pam.argtypes = [
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_int
        ]
except Exception:
    _C_LIB = None


# -----------------------------------------------------------------------------
# 1. Uniform Sequence Expansion & Centered Binomial Error Sampling
# -----------------------------------------------------------------------------

def expand_public_sequence_a(seed: bytes, length: int = TOTAL_A_LEN) -> np.ndarray:
    """
    Expands a cryptographically uniform pseudorandom sequence a in Z_4096^length
    from a 32-byte seed using SHAKE-256. Zero-rejection masking guaranteed.
    """
    shake = hashlib.shake_256(seed)
    raw = shake.digest(length * 2)
    arr = np.frombuffer(raw, dtype="<u2")
    return (arr[:length] & Q_MASK).astype(np.int64)


def sample_cbd2_from_bytes(raw_bytes: bytes, count: int) -> np.ndarray:
    """
    Samples count integers from Centered Binomial Distribution CBD_eta (eta=2).
    Input: count bytes of uniform entropy.
    Output: values in {-2, -1, 0, 1, 2} with exact binomial weights:
            P(0)=6/16, P(+/-1)=4/16, P(+/-2)=1/16.
    """
    assert len(raw_bytes) >= count, f"CBD buffer underflow: need {count} bytes, got {len(raw_bytes)}"
    raw = np.frombuffer(raw_bytes[:count], dtype=np.uint8)
    
    raw_int = raw.astype(np.int64)
    a0 = (raw_int >> 0) & 1
    a1 = (raw_int >> 1) & 1
    b0 = (raw_int >> 2) & 1
    b1 = (raw_int >> 3) & 1
    
    samples = (a0 + a1) - (b0 + b1)
    return samples


# -----------------------------------------------------------------------------
# 2. Canonical 12-Bit Packing and Unpacking
# -----------------------------------------------------------------------------

def pack_12bit(arr: np.ndarray) -> bytes:
    """
    Packs an array of integers in [0, 4095] into compact 12-bit binary representation.
    2 integers (24 bits) map to 3 bytes. Array length must be even.
    """
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
    """
    Unpacks a 12-bit binary buffer into count 16-bit integers in [0, 4095].
    Count must be even. Strict canonical validation (< 4096).
    """
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


# -----------------------------------------------------------------------------
# 3. 4-PAM Message Constellation Encoding & Branchless Voronoi Decoding
# -----------------------------------------------------------------------------

def encode_message_4pam_256(m_bytes: bytes, window_size: int = W) -> np.ndarray:
    """
    Encodes a 256-bit (32-byte) message into a vector of 128 coordinates over Z_4096.
    Every 2 bits are mapped to one of 4 constellation points: {0, 1024, 2048, 3072}.
    """
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
    """
    Decodes a 128-element noisy vector into 256 bits (32 bytes) of message.
    Uses branchless Voronoi decision logic: ((w + 512) & 0x0FFF) >> 10.
    """
    if len(noisy_vector) != window_size:
        raise ValueError(f"Input vector length mismatch: expected {window_size}, got {len(noisy_vector)}")

    if _C_LIB is not None and window_size == W:
        w_c = np.ascontiguousarray(noisy_vector, dtype=np.uint16)
        out_buf = bytearray(32)
        _C_LIB.hankel_neon_decode_4pam(
            w_c.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            (ctypes.c_uint8 * 32).from_buffer(out_buf),
            window_size
        )
        return bytes(out_buf)

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


# -----------------------------------------------------------------------------
# 4. Windowed Hankel Linear Algebra Primitives
# -----------------------------------------------------------------------------

def hankel_forward_multiply(a_seq: np.ndarray, x: np.ndarray, n: int = N, m: int = M_LEN) -> np.ndarray:
    """
    Computes y = H(a) * x mod q, where H is the (m x n) Hankel operator:
    H_{i, j} = a_{i + j}.
    Length of a_seq must be at least m + n - 1.
    """
    assert len(x) == n, f"Input x length mismatch: expected {n}, got {len(x)}"
    assert len(a_seq) >= m + n - 1, f"Sequence a length underflow: need {m + n - 1}, got {len(a_seq)}"
    
    if _C_LIB is not None:
        y = np.empty(m, dtype=np.uint16)
        a_c = np.ascontiguousarray(a_seq, dtype=np.uint16)
        x_c = np.ascontiguousarray(x, dtype=np.int16)
        _C_LIB.hankel_neon_forward_mul(
            a_c.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            x_c.ctypes.data_as(ctypes.POINTER(ctypes.c_int16)),
            None,
            y.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            n,
            m
        )
        return y.astype(np.int64)

    y = np.empty(m, dtype=np.int64)
    for i in range(m):
        y[i] = np.dot(a_seq[i : i + n], x) & Q_MASK
    return y


def hankel_window_project(x: np.ndarray, y_ext: np.ndarray, n: int = N, w_len: int = W) -> np.ndarray:
    """
    Computes the W-dimensional projection vector:
    K_w = sum_{i=0}^{n-1} x_i * y_ext_{i + w} mod q  for w in [0, W - 1].
    Length of y_ext must be at least n + w_len.
    """
    assert len(x) == n, f"Input x length mismatch: expected {n}, got {len(x)}"
    assert len(y_ext) >= n + w_len, f"y_ext length underflow: need {n + w_len}, got {len(y_ext)}"

    if _C_LIB is not None:
        K = np.empty(w_len, dtype=np.uint16)
        x_c = np.ascontiguousarray(x, dtype=np.int16)
        y_c = np.ascontiguousarray(y_ext, dtype=np.uint16)
        _C_LIB.hankel_neon_window_project(
            x_c.ctypes.data_as(ctypes.POINTER(ctypes.c_int16)),
            y_c.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            K.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            n,
            w_len
        )
        return K.astype(np.int64)

    K = np.empty(w_len, dtype=np.int64)
    for w in range(w_len):
        K[w] = np.dot(x, y_ext[w : w + n]) & Q_MASK
    return K


# -----------------------------------------------------------------------------
# 5. CPA KeyGen, Encapsulation, and Decapsulation
# -----------------------------------------------------------------------------

def hankel_kem_cpa_keygen(
    seed: Optional[bytes] = None,
    n: int = N,
    w_len: int = W
) -> Tuple[bytes, np.ndarray, np.ndarray]:
    """
    CPA KeyGen:
    1. Derives seed_a and seed_noise from 64-byte entropy.
    2. Expands public sequence a of length 2n + W - 1.
    3. Samples secret s in Z^n and error e in Z^(n + W) from CBD_2.
    4. Computes public key vector b = H(a) * s + e mod q.
    Returns: (seed_a, b, s)
    """
    if seed is None:
        seed = os.urandom(64)
    elif len(seed) < 64:
        seed = hashlib.shake_256(seed + b"_hankel_cpa_keygen_seed").digest(64)

    seed_a = seed[:32]
    seed_noise = seed[32:64]

    total_a = 2 * n + w_len - 1
    a_seq = expand_public_sequence_a(seed_a, total_a)

    m = n + w_len
    buf_noise = hashlib.shake_256(seed_noise + b"_hankel_noise").digest(n + m)
    s = sample_cbd2_from_bytes(buf_noise[:n], n)
    e = sample_cbd2_from_bytes(buf_noise[n : n + m], m)

    # Constant-time mitigation against catastrophic RNG failure (all-zero secret)
    s_or = int(np.bitwise_or.reduce(np.abs(s)))
    is_s_zero = 1 ^ int(bool(s_or))
    s[0] |= is_s_zero  # Force s[0] to 1 if s was completely empty

    b = (hankel_forward_multiply(a_seq, s, n=n, m=m) + e) & Q_MASK
    return seed_a, b, s


def hankel_kem_cpa_encaps(
    seed_a: bytes,
    b: np.ndarray,
    msg: bytes,
    coins: bytes,
    n: int = N,
    w_len: int = W
) -> Tuple[np.ndarray, np.ndarray]:
    """
    CPA Encapsulation:
    1. Expands public sequence a from seed_a.
    2. Samples ephemeral r in Z^n and error e1 in Z^(n + W) from CBD_2.
    3. Computes ciphertext vector u = H(a) * r + e1 mod q.
    4. Computes shared vector K_bob = Project(r, b).
    5. Modulates 4-PAM message onto K_bob: v = K_bob + Encode(msg) mod q.
    Returns: (u, v)
    """
    total_a = 2 * n + w_len - 1
    a_seq = expand_public_sequence_a(seed_a, total_a)

    m = n + w_len
    buf_coins = hashlib.shake_256(coins + b"_hankel_encaps_coins").digest(n + m + w_len)
    r = sample_cbd2_from_bytes(buf_coins[:n], n)
    e1 = sample_cbd2_from_bytes(buf_coins[n : n + m], m)
    e2 = sample_cbd2_from_bytes(buf_coins[n + m : n + m + w_len], w_len)

    u = (hankel_forward_multiply(a_seq, r, n=n, m=m) + e1) & Q_MASK
    K_bob = hankel_window_project(r, b, n=n, w_len=w_len)
    M_enc = encode_message_4pam_256(msg, window_size=w_len)
    v = (K_bob + M_enc + e2) & Q_MASK

    return u, v


def hankel_kem_cpa_decaps(
    s: np.ndarray,
    u: np.ndarray,
    v: np.ndarray,
    n: int = N,
    w_len: int = W
) -> bytes:
    """
    CPA Decapsulation:
    1. Computes candidate shared vector K_alice = Project(s, u).
    2. Recovers noisy message: W = (v - K_alice) mod q.
    3. Decodes message m via 4-PAM Voronoi decision rule.
    Returns: msg (32 bytes)
    """
    K_alice = hankel_window_project(s, u, n=n, w_len=w_len)
    W_noisy = (v - K_alice) & Q_MASK
    return decode_message_4pam_256(W_noisy, window_size=w_len)
