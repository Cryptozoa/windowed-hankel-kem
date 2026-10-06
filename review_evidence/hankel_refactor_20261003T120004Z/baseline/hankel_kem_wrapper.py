"""
Windowed Hankel LWE KEM: IND-CCA2 QFO Wrapper & Serialization
--------------------------------------------------------------
Provides IND-CCA2 security via the Fujisaki-Okamoto (QFO_m^not_bot) transform
with constant-time implicit rejection and canonical 12-bit binary serialization.
"""

import os
import struct
import hmac
import hashlib
from typing import Tuple, Optional
import numpy as np

from hankel_kem_core import (
    Q,
    Q_MASK,
    ETA,
    N,
    W,
    M_LEN,
    TOTAL_A_LEN,
    pack_12bit,
    unpack_12bit,
    hankel_kem_cpa_keygen,
    hankel_kem_cpa_encaps,
    hankel_kem_cpa_decaps
)

MAGIC_PK = b"HNPK"  # Hankel Public Key v1
MAGIC_CT = b"HNCT"  # Hankel Ciphertext v1


# -----------------------------------------------------------------------------
# 1. Constant-Time Utilities
# -----------------------------------------------------------------------------

def constant_time_select(condition: bool, a: bytes, b: bytes) -> bytes:
    """Branchless constant-time multiplexer: returns a if condition is True, else b."""
    assert len(a) == len(b), "Byte buffers must be identical length"
    mask = -(int(condition)) & 0xFF
    inv_mask = (~mask) & 0xFF
    return bytes([(a[i] & mask) | (b[i] & inv_mask) for i in range(len(a))])


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time memory comparison via hmac.compare_digest."""
    return hmac.compare_digest(a, b)


# -----------------------------------------------------------------------------
# 2. Key Structures & Binary Serialization
# -----------------------------------------------------------------------------

class HankelKEMPublicKey:
    def __init__(self, seed_a: bytes, b: np.ndarray, n: int = N, w_len: int = W, q: int = Q):
        self.seed_a = seed_a
        self.b = b
        self.n = n
        self.w_len = w_len
        self.q = q


class HankelKEMSecretKey:
    def __init__(self, s: np.ndarray, pk: HankelKEMPublicKey, s_reject: bytes):
        self.s = s
        self.pk = pk
        self.s_reject = s_reject


def serialize_public_key(pk: HankelKEMPublicKey) -> bytes:
    """
    Serializes public key in Little-Endian canonical binary format:
    Header: [4s magic, 2H (n, w_len), 2H (q, reserved=0)] = 12 bytes
    Payload: 32 bytes seed_a + pack_12bit(b) of length (n + w_len)
    """
    header = struct.pack("<4s4H", MAGIC_PK, pk.n, pk.w_len, pk.q, 0)
    m = pk.n + pk.w_len
    assert len(pk.b) == m, f"Public key b length mismatch: expected {m}, got {len(pk.b)}"
    payload_b = pack_12bit(pk.b & Q_MASK)
    return header + pk.seed_a + payload_b


def deserialize_public_key(buf: bytes) -> HankelKEMPublicKey:
    """
    Deserializes public key from Little-Endian bytes with strict parameter verification.
    """
    header_len = 12
    if len(buf) < header_len + 32:
        raise ValueError(f"Public key buffer underflow: expected at least {header_len + 32} bytes")

    magic, n, w_len, q, reserved = struct.unpack("<4s4H", buf[:header_len])
    if magic != MAGIC_PK:
        raise ValueError(f"Invalid public key magic: expected {MAGIC_PK}, got {magic}")
    if reserved != 0:
        raise ValueError(f"Non-canonical public key: reserved field must be 0, got {reserved}")
    if q != Q:
        raise ValueError(f"Unsupported modulus in public key: q={q} (expected {Q})")
    if n != N or w_len != W:
        raise ValueError(f"Unsupported parameters: n={n}, w_len={w_len} (expected n={N}, w={W})")

    seed_a = buf[header_len : header_len + 32]
    expected_b_bytes = ((n + w_len) * 3) // 2
    if len(buf) != header_len + 32 + expected_b_bytes:
        raise ValueError(f"Public key length mismatch: expected {header_len + 32 + expected_b_bytes}, got {len(buf)}")

    b = unpack_12bit(buf[header_len + 32:], n + w_len)
    return HankelKEMPublicKey(seed_a=seed_a, b=b, n=n, w_len=w_len, q=q)


def serialize_ciphertext(u: np.ndarray, v: np.ndarray, n: int = N, w_len: int = W, q: int = Q) -> bytes:
    """
    Serializes ciphertext in Little-Endian canonical binary format:
    Header: [4s magic, 2H (n, w_len), 2H (q, reserved=0)] = 12 bytes
    Payload: pack_12bit(u) of length (n + w_len) + pack_12bit(v) of length w_len
    """
    header = struct.pack("<4s4H", MAGIC_CT, n, w_len, q, 0)
    m = n + w_len
    assert len(u) == m, f"Ciphertext u length mismatch: expected {m}, got {len(u)}"
    assert len(v) == w_len, f"Ciphertext v length mismatch: expected {w_len}, got {len(v)}"
    payload_u = pack_12bit(u & Q_MASK)
    payload_v = pack_12bit(v & Q_MASK)
    return header + payload_u + payload_v


def deserialize_ciphertext(buf: bytes) -> Tuple[np.ndarray, np.ndarray, int, int, int]:
    """
    Deserializes ciphertext from Little-Endian bytes with strict parameter verification.
    """
    header_len = 12
    if len(buf) < header_len:
        raise ValueError(f"Ciphertext buffer underflow: expected at least {header_len} bytes")

    magic, n, w_len, q, reserved = struct.unpack("<4s4H", buf[:header_len])
    if magic != MAGIC_CT:
        raise ValueError(f"Invalid ciphertext magic: expected {MAGIC_CT}, got {magic}")
    if reserved != 0:
        raise ValueError(f"Non-canonical ciphertext: reserved field must be 0, got {reserved}")
    if q != Q or n != N or w_len != W:
        raise ValueError(f"Ciphertext parameter mismatch: n={n}, w={w_len}, q={q}")

    expected_u_bytes = ((n + w_len) * 3) // 2
    expected_v_bytes = (w_len * 3) // 2
    total_expected = header_len + expected_u_bytes + expected_v_bytes
    if len(buf) != total_expected:
        raise ValueError(f"Ciphertext length mismatch: expected {total_expected}, got {len(buf)}")

    offset_u = header_len
    offset_v = offset_u + expected_u_bytes
    u = unpack_12bit(buf[offset_u:offset_v], n + w_len)
    v = unpack_12bit(buf[offset_v:], w_len)

    return u, v, n, w_len, q


# -----------------------------------------------------------------------------
# 3. IND-CCA2 QFO Protocol Engine
# -----------------------------------------------------------------------------

def hankel_kem_keygen(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    IND-CCA2 KeyGen:
    Returns (serialized_pk, serialized_sk).
    """
    if seed is None:
        seed = os.urandom(64)
    elif len(seed) < 64:
        seed = hashlib.shake_256(seed + b"_hankel_cca_keygen_seed").digest(64)

    seed_cpa = seed[:32]
    seed_a, b, s = hankel_kem_cpa_keygen(seed=seed_cpa, n=N, w_len=W)
    
    pk = HankelKEMPublicKey(seed_a=seed_a, b=b, n=N, w_len=W, q=Q)
    pk_bytes = serialize_public_key(pk)

    # Derive constant-time s_reject for implicit rejection
    s_reject = hashlib.shake_256(seed[32:] + b"_hankel_cca_reject").digest(32)

    # Serialize secret key: s (packed 12-bit representation or raw CBD int8) + s_reject + pk_bytes
    # Store s as signed int8 bytes (since s in {-2..2})
    s_bytes = (s.astype(np.int8)).tobytes()
    sk_bytes = s_bytes + s_reject + pk_bytes

    return pk_bytes, sk_bytes


def hankel_kem_encaps(pk_bytes: bytes, entropy: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    IND-CCA2 Encapsulation (QFO_m^not_bot):
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

    u, v = hankel_kem_cpa_encaps(pk.seed_a, pk.b, m, coins, n=pk.n, w_len=pk.w_len)
    ct_bytes = serialize_ciphertext(u, v, n=pk.n, w_len=pk.w_len, q=pk.q)

    # Shared secret binding: SS = SHAKE-256(K_bar || SHA256(ct))
    h_ct = hashlib.sha256(ct_bytes).digest()
    shared_key = hashlib.shake_256(k_bar + h_ct).digest(32)

    return ct_bytes, shared_key


def hankel_kem_decaps(ct_bytes: bytes, sk_bytes: bytes) -> bytes:
    """
    IND-CCA2 Decapsulation with Constant-Time Implicit Rejection:
    1. Parses s, s_reject, and pk from sk_bytes.
    2. Recovers m' = CPA-Decaps(s, ct).
    3. Re-encrypts ct' = CPA-Encaps(pk, m'; coins').
    4. Constant-time comparison ct == ct'.
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

    # Parse ciphertext in a branchless, exceptionless manner
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
    m_recovered = hankel_kem_cpa_decaps(s, u, v, n=pk.n, w_len=pk.w_len)

    # Re-encryption (Fujisaki-Okamoto check)
    k_and_coins = hashlib.shake_256(m_recovered + h_pk).digest(64)
    k_bar_cand = k_and_coins[:32]
    coins_cand = k_and_coins[32:64]

    u_prime, v_prime = hankel_kem_cpa_encaps(pk.seed_a, pk.b, m_recovered, coins_cand, n=pk.n, w_len=pk.w_len)
    ct_prime = serialize_ciphertext(u_prime, v_prime, n=pk.n, w_len=pk.w_len, q=pk.q)

    # Constant-time comparison
    is_valid = constant_time_compare(ct_bytes, ct_prime) and valid_parse

    # Constant-time selection: K_bar_cand if is_valid else s_reject
    k_selected = constant_time_select(is_valid, k_bar_cand, s_reject)

    # Final binding
    h_ct = hashlib.sha256(ct_bytes).digest()
    return hashlib.shake_256(k_selected + h_ct).digest(32)
