"""The frozen Windowed Hankel CPA equations; backend changes preserve outputs.

This research implementation does not claim that the current parameter/noise
profile instantiates a published security reduction.
"""
import os
import hashlib
from typing import Optional, Tuple
import numpy as np
from .params import N, W, Q_MASK
from .sampling import expand_public_sequence_a, sample_cbd2_from_bytes
from .codec import encode_message_4pam_256
from .operators import hankel_forward_multiply, hankel_window_project, decode_message_4pam_256

def hankel_kem_cpa_keygen(
    seed: Optional[bytes] = None,
    n: int = N,
    w_len: int = W,
    *, backend=None, sampler=None, expander=None
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

    sampler = sample_cbd2_from_bytes if sampler is None else sampler
    expander = expand_public_sequence_a if expander is None else expander
    total_a = 2 * n + w_len - 1
    a_seq = expander(seed_a, total_a)

    m = n + w_len
    buf_noise = hashlib.shake_256(seed_noise + b"_hankel_noise").digest(n + m)
    s = sampler(buf_noise[:n], n)
    e = sampler(buf_noise[n : n + m], m)

    # Preserve the existing all-zero-secret handling. This Python operation
    # has no established constant-time guarantee.
    s_or = int(np.bitwise_or.reduce(np.abs(s)))
    is_s_zero = 1 ^ int(bool(s_or))
    s[0] |= is_s_zero  # Force s[0] to 1 if every secret coordinate was zero.

    b = hankel_forward_multiply(a_seq, s, n=n, m=m, backend=backend, error=e)
    return seed_a, b, s


def hankel_kem_cpa_encaps(
    seed_a: bytes,
    b: np.ndarray,
    msg: bytes,
    coins: bytes,
    n: int = N,
    w_len: int = W,
    *, backend=None, sampler=None, expander=None
) -> Tuple[np.ndarray, np.ndarray]:
    """
    CPA Encapsulation:
    1. Expands public sequence a from seed_a.
    2. Samples ephemeral r in Z^n and error e1 in Z^(n + W) from CBD_2.
    3. Computes ciphertext vector u = H(a) * r + e1 mod q.
    4. Computes shared vector K_bob = Project(r, b).
    5. Modulates 4-PAM message with fresh error:
       v = K_bob + Encode(msg) + e2 mod q.
    Returns: (u, v)
    """
    sampler = sample_cbd2_from_bytes if sampler is None else sampler
    expander = expand_public_sequence_a if expander is None else expander
    total_a = 2 * n + w_len - 1
    a_seq = expander(seed_a, total_a)

    m = n + w_len
    buf_coins = hashlib.shake_256(coins + b"_hankel_encaps_coins").digest(n + m + w_len)
    r = sampler(buf_coins[:n], n)
    e1 = sampler(buf_coins[n : n + m], m)
    e2 = sampler(buf_coins[n + m : n + m + w_len], w_len)

    u = hankel_forward_multiply(a_seq, r, n=n, m=m, backend=backend, error=e1)
    K_bob = hankel_window_project(r, b, n=n, w_len=w_len, backend=backend)
    M_enc = encode_message_4pam_256(msg, window_size=w_len)
    v = (K_bob + M_enc + e2) & Q_MASK

    return u, v


def hankel_kem_cpa_decaps(
    s: np.ndarray,
    u: np.ndarray,
    v: np.ndarray,
    n: int = N,
    w_len: int = W,
    *, backend=None, sampler=None, expander=None
) -> bytes:
    """
    CPA Decapsulation:
    1. Computes candidate shared vector K_alice = Project(s, u).
    2. Recovers noisy message: W = (v - K_alice) mod q.
    3. Decodes message m via 4-PAM Voronoi decision rule.
    Returns: msg (32 bytes)
    """
    K_alice = hankel_window_project(s, u, n=n, w_len=w_len, backend=backend)
    W_noisy = (v - K_alice) & Q_MASK
    return decode_message_4pam_256(W_noisy, window_size=w_len, backend=backend)
