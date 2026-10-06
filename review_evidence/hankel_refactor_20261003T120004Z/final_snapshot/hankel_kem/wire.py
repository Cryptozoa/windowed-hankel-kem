"""Legacy Hankel key structures and exact 12-bit wire serialization."""

import struct
from typing import Tuple

import numpy as np

from .params import N, W, Q, Q_MASK
from .codec import pack_12bit, unpack_12bit

MAGIC_PK = b"HNPK"
MAGIC_CT = b"HNCT"


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
