"""Existing Fujisaki-Okamoto composition and functional implicit rejection.

The Python byte-selection helper is a functional reference; no interpreter
constant-time guarantee is made here. Wire bytes and derivation tags are legacy.
"""

import os
import struct
import hmac
import hashlib
from typing import Tuple, Optional

import numpy as np

from .params import N, W, Q
from .codec import unpack_12bit
from .wire import (
    MAGIC_CT, HankelKEMPublicKey, serialize_public_key, deserialize_public_key,
    serialize_ciphertext,
)
from hankel_kem_core import (
    hankel_kem_cpa_keygen, hankel_kem_cpa_encaps, hankel_kem_cpa_decaps,
)


def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
    """Select a if condition is True, else b, using functional Python byte masks."""
    assert len(a) == len(b), "Byte buffers must be identical length"
    mask = -(int(condition)) & 0xFF
    inv_mask = (~mask) & 0xFF
    return bytes([(a[i] & mask) | (b[i] & inv_mask) for i in range(len(a))])


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare byte buffers using hmac.compare_digest."""
    return hmac.compare_digest(a, b)


def hankel_kem_keygen(seed: Optional[bytes] = None, *, backend=None) -> Tuple[bytes, bytes]:
    """
    Fujisaki-Okamoto composition KeyGen:
    Returns (serialized_pk, serialized_sk).
    """
    if seed is None:
        seed = os.urandom(64)
    elif len(seed) < 64:
        seed = hashlib.shake_256(seed + b"_hankel_cca_keygen_seed").digest(64)

    seed_cpa = seed[:32]
    seed_a, b, s = hankel_kem_cpa_keygen(seed=seed_cpa, n=N, w_len=W, backend=backend)
    
    pk = HankelKEMPublicKey(seed_a=seed_a, b=b, n=N, w_len=W, q=Q)
    pk_bytes = serialize_public_key(pk)

    # Derive s_reject for implicit rejection
    s_reject = hashlib.shake_256(seed[32:] + b"_hankel_cca_reject").digest(32)

    # Serialize secret key: s (packed 12-bit representation or raw CBD int8) + s_reject + pk_bytes
    # Store s as signed int8 bytes (since s in {-2..2})
    s_bytes = (s.astype(np.int8)).tobytes()
    sk_bytes = s_bytes + s_reject + pk_bytes

    return pk_bytes, sk_bytes


def hankel_kem_encaps(pk_bytes: bytes, entropy: Optional[bytes] = None, *, backend=None) -> Tuple[bytes, bytes]:
    """
    Fujisaki-Okamoto composition Encapsulation:
    1. Deserializes public key.
    2. Samples uniform random 32-byte message m.
    3. Hashes m || H(pk) via SHAKE-256 to derive (K_bar, coins).
    4. Deterministically encrypts CPA ciphertext (u, v) using coins.
    5. Final shared key: SS = SHAKE-256(K_bar || H(ct)).
    Returns: (ciphertext_bytes, shared_key_32_bytes).
    """
    pk = deserialize_public_key(pk_bytes)
    h_pk = hashlib.sha256(pk_bytes).digest()

    if entropy is None:
        m = os.urandom(32)
    else:
        m = hashlib.shake_256(entropy + b"_hankel_encaps_entropy").digest(32)

    # Derivation of (K_bar, coins)
    k_and_coins = hashlib.shake_256(m + h_pk).digest(64)
    k_bar = k_and_coins[:32]
    coins = k_and_coins[32:64]

    u, v = hankel_kem_cpa_encaps(pk.seed_a, pk.b, m, coins, n=pk.n, w_len=pk.w_len, backend=backend)
    ct_bytes = serialize_ciphertext(u, v, n=pk.n, w_len=pk.w_len, q=pk.q)

    # Shared secret binding: SS = SHAKE-256(K_bar || SHA256(ct))
    h_ct = hashlib.sha256(ct_bytes).digest()
    shared_key = hashlib.shake_256(k_bar + h_ct).digest(32)

    return ct_bytes, shared_key


def hankel_kem_decaps(ct_bytes: bytes, sk_bytes: bytes, *, backend=None) -> bytes:
    """
    Fujisaki-Okamoto composition Decapsulation with implicit rejection:
    1. Parses s, s_reject, and pk from sk_bytes.
    2. Recovers m' = CPA-Decaps(s, ct).
    3. Re-encrypts ct' = CPA-Encaps(pk, m'; coins').
    4. Compare ct == ct' via hmac.compare_digest.
    5. If match: SS = SHAKE-256(K_bar' || H(ct)).
       If mismatch: SS = SHAKE-256(s_reject || H(ct)).
    """
    expected_s_len = N
    expected_reject_len = 32
    if len(sk_bytes) < expected_s_len + expected_reject_len:
        raise ValueError("Secret key buffer underflow")

    s_raw = sk_bytes[:expected_s_len]
    s_reject = sk_bytes[expected_s_len : expected_s_len + expected_reject_len]
    pk_bytes = sk_bytes[expected_s_len + expected_reject_len:]

    s = np.frombuffer(s_raw, dtype=np.int8).astype(np.int64)
    pk = deserialize_public_key(pk_bytes)
    h_pk = hashlib.sha256(pk_bytes).digest()

    # Normalize ciphertext length for candidate parsing without unpack exceptions
    expected_u_bytes = ((pk.n + pk.w_len) * 3) // 2
    expected_v_bytes = (pk.w_len * 3) // 2
    total_expected = 12 + expected_u_bytes + expected_v_bytes

    # Pad or truncate buffer to exact expected length to avoid Python slice/unpack exceptions
    if len(ct_bytes) >= total_expected:
        safe_ct = ct_bytes[:total_expected]
        len_valid = int(len(ct_bytes) == total_expected)
    else:
        safe_ct = ct_bytes + b"\x00" * (total_expected - len(ct_bytes))
        len_valid = 0

    magic, parsed_n, parsed_w, parsed_q, reserved = struct.unpack("<4s4H", safe_ct[:12])
    
    magic_valid = int(magic == MAGIC_CT)
    res_valid = int(reserved == 0)
    params_valid = int(parsed_q == pk.q and parsed_n == pk.n and parsed_w == pk.w_len)
    
    valid_parse = bool(len_valid & magic_valid & res_valid & params_valid)

    offset_u = 12
    offset_v = offset_u + expected_u_bytes
    
    # We can safely unpack because safe_ct is guaranteed to be exactly total_expected length
    u = unpack_12bit(safe_ct[offset_u:offset_v], pk.n + pk.w_len)
    v = unpack_12bit(safe_ct[offset_v:], pk.w_len)

    # CPA decapsulation to recover candidate message
    m_recovered = hankel_kem_cpa_decaps(s, u, v, n=pk.n, w_len=pk.w_len, backend=backend)

    # Re-encryption (Fujisaki-Okamoto check)
    k_and_coins = hashlib.shake_256(m_recovered + h_pk).digest(64)
    k_bar_cand = k_and_coins[:32]
    coins_cand = k_and_coins[32:64]

    u_prime, v_prime = hankel_kem_cpa_encaps(pk.seed_a, pk.b, m_recovered, coins_cand, n=pk.n, w_len=pk.w_len, backend=backend)
    ct_prime = serialize_ciphertext(u_prime, v_prime, n=pk.n, w_len=pk.w_len, q=pk.q)

    # Ciphertext comparison
    is_valid = constant_time_compare(ct_bytes, ct_prime) and valid_parse

    # Functional selection: K_bar_cand if is_valid else s_reject
    k_selected = constant_time_select(is_valid, k_bar_cand, s_reject)

    # Final binding
    h_ct = hashlib.sha256(ct_bytes).digest()
    return hashlib.shake_256(k_selected + h_ct).digest(32)
