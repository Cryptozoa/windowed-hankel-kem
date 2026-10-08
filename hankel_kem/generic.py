"""Parameterized reference implementation of Windowed Hankel KEM for every registered parameter set.

One straightforward implementation of the full KEM (Algorithms 1-6 of the paper) for any profile in
PROFILES. For WH-640 it reproduces the original implementation (hankel_kem/fo.py) byte for byte,
including its KAT fixtures; WH-936 and WH-1208 are the Category 3 and 5 sets of Appendix D.

Differences between profiles: n, q (and hence the coefficient width and the 4-PAM scaling), and a
domain string appended to every derivation tag (empty for WH-640, so that its outputs are unchanged).
The secret and noise distribution is CBD_2 and the window is W = 128 (a 256-bit message) throughout.
"""

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np

MAGIC_PK = b"HNPK"
MAGIC_CT = b"HNCT"
HEADER_BYTES = 12
SEED_BYTES = 32


@dataclass(frozen=True)
class Profile:
    name: str
    n: int
    q: int
    domain: bytes
    w: int = 128
    eta: int = 2

    @property
    def m(self) -> int:
        return self.n + self.w

    @property
    def L(self) -> int:
        return 2 * self.n + self.w - 1

    @property
    def log_q(self) -> int:
        return self.q.bit_length() - 1

    @property
    def mask(self) -> int:
        return self.q - 1

    @property
    def pk_bytes(self) -> int:
        return HEADER_BYTES + SEED_BYTES + self.m * self.log_q // 8

    @property
    def ct_bytes(self) -> int:
        return HEADER_BYTES + (self.m + self.w) * self.log_q // 8

    @property
    def sk_bytes(self) -> int:
        return self.n + 32 + self.pk_bytes


WH640 = Profile("WH-640", n=640, q=4096, domain=b"")
WH936 = Profile("WH-936", n=936, q=8192, domain=b"_wh936")
WH1208 = Profile("WH-1208", n=1208, q=8192, domain=b"_wh1208")
PROFILES = {p.name: p for p in (WH640, WH936, WH1208)}

for _p in PROFILES.values():
    assert _p.q & (_p.q - 1) == 0 and _p.n % 8 == 0 and _p.m % 8 == 0
    assert (_p.m * _p.log_q) % 8 == 0 and (_p.w * _p.log_q) % 8 == 0


def _tag(p: Profile, label: bytes) -> bytes:
    return label + p.domain


def shake(data: bytes, n: int) -> bytes:
    return hashlib.shake_256(data).digest(n)


# --- encoding -----------------------------------------------------------------------------------

def pack_bits(values, bits: int) -> bytes:
    """Little-endian bit stream: value i occupies bits [i*bits, (i+1)*bits) (LSB first)."""
    acc = 0
    for i, v in enumerate(values):
        acc |= (int(v) & ((1 << bits) - 1)) << (i * bits)
    nbytes = (len(values) * bits + 7) // 8
    return acc.to_bytes(nbytes, "little")


def unpack_bits(buf: bytes, count: int, bits: int) -> np.ndarray:
    acc = int.from_bytes(buf, "little")
    mask = (1 << bits) - 1
    return np.array([(acc >> (i * bits)) & mask for i in range(count)], dtype=np.int64)


def header(magic: bytes, p: Profile) -> bytes:
    return struct.pack("<4s4H", magic, p.n, p.w, p.q, 0)


# --- sampling and arithmetic --------------------------------------------------------------------

def expand_a(p: Profile, seed_a: bytes) -> np.ndarray:
    raw = shake(seed_a, 2 * p.L)
    return (np.frombuffer(raw, dtype="<u2").astype(np.int64) & p.mask)


def cbd2(buf: bytes) -> np.ndarray:
    b = np.frombuffer(buf, dtype=np.uint8).astype(np.int64)
    return ((b & 1) + ((b >> 1) & 1)) - (((b >> 2) & 1) + ((b >> 3) & 1))


def hankel_mul(p: Profile, a: np.ndarray, x: np.ndarray, rows: int, e: Optional[np.ndarray] = None) -> np.ndarray:
    """out[i] = sum_{j<n} a[i+j] x[j] (+ e[i]) mod q, for i < rows."""
    full = np.convolve(a[: rows + p.n - 1], x[::-1])[p.n - 1: p.n - 1 + rows]
    if e is not None:
        full = full + e
    return full & p.mask


def pam_encode(p: Profile, msg: bytes) -> np.ndarray:
    syms = np.array([(msg[i >> 2] >> (2 * (i & 3))) & 3 for i in range(p.w)], dtype=np.int64)
    return syms << (p.log_q - 2)


def pam_decode(p: Profile, w: np.ndarray) -> bytes:
    syms = (((w & p.mask) + p.q // 8) & p.mask) >> (p.log_q - 2)
    out = bytearray(32)
    for i in range(p.w):
        out[i >> 2] |= int(syms[i]) << (2 * (i & 3))
    return bytes(out)


# --- CPA scheme ---------------------------------------------------------------------------------

def cpa_keygen(p: Profile, seed_cpa: bytes):
    cs = shake(seed_cpa + _tag(p, b"_hankel_cpa_keygen_seed"), 64)
    seed_a, seed_noise = cs[:32], cs[32:]
    a = expand_a(p, seed_a)
    noise = shake(seed_noise + _tag(p, b"_hankel_noise"), p.n + p.m)
    s, e = cbd2(noise[: p.n]), cbd2(noise[p.n:])
    if not s.any():
        s[0] = 1  # as the original implementation (probability 2^-905.6 for n = 640)
    b = hankel_mul(p, a, s, p.m, e)
    return seed_a, b, s


def cpa_encrypt(p: Profile, seed_a: bytes, b: np.ndarray, msg: bytes, coins: bytes) -> bytes:
    a = expand_a(p, seed_a)
    g = shake(coins + _tag(p, b"_hankel_encaps_coins"), p.n + p.m + p.w)
    r, e1, e2 = cbd2(g[: p.n]), cbd2(g[p.n: p.n + p.m]), cbd2(g[p.n + p.m:])
    u = hankel_mul(p, a, r, p.m, e1)
    k = hankel_mul(p, b, r, p.w)
    v = (k + pam_encode(p, msg) + e2) & p.mask
    return header(MAGIC_CT, p) + pack_bits(u, p.log_q) + pack_bits(v, p.log_q)


def cpa_decrypt(p: Profile, s: np.ndarray, ct: bytes) -> bytes:
    ub = p.m * p.log_q // 8
    u = unpack_bits(ct[HEADER_BYTES: HEADER_BYTES + ub], p.m, p.log_q)
    v = unpack_bits(ct[HEADER_BYTES + ub:], p.w, p.log_q)
    k = hankel_mul(p, u, s, p.w)
    return pam_decode(p, (v - k) & p.mask)


# --- KEM ----------------------------------------------------------------------------------------

def keygen(p: Profile, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if seed is None:
        seed = os.urandom(64)
    elif len(seed) < 64:
        seed = shake(seed + _tag(p, b"_hankel_cca_keygen_seed"), 64)
    seed_a, b, s = cpa_keygen(p, seed[:32])
    pk = header(MAGIC_PK, p) + seed_a + pack_bits(b, p.log_q)
    z = shake(seed[32:] + _tag(p, b"_hankel_cca_reject"), 32)
    sk = s.astype(np.int8).tobytes() + z + pk
    return pk, sk


def _parse_pk(p: Profile, pk: bytes):
    if len(pk) != p.pk_bytes or pk[:HEADER_BYTES] != header(MAGIC_PK, p):
        raise ValueError("Malformed public key")
    return pk[HEADER_BYTES: HEADER_BYTES + SEED_BYTES], unpack_bits(pk[HEADER_BYTES + SEED_BYTES:], p.m, p.log_q)


def encaps(p: Profile, pk: bytes, entropy: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    seed_a, b = _parse_pk(p, pk)
    msg = os.urandom(32) if entropy is None else shake(entropy + _tag(p, b"_hankel_encaps_entropy"), 32)
    kc = shake(msg + hashlib.sha256(pk).digest(), 64)
    ct = cpa_encrypt(p, seed_a, b, msg, kc[32:])
    return ct, shake(kc[:32] + hashlib.sha256(ct).digest(), 32)


def decaps(p: Profile, ct: bytes, sk: bytes) -> bytes:
    if len(sk) != p.sk_bytes:
        raise ValueError("Malformed secret key")
    s = np.frombuffer(sk[: p.n], dtype=np.int8).astype(np.int64)
    z, pk = sk[p.n: p.n + 32], sk[p.n + 32:]
    seed_a, b = _parse_pk(p, pk)
    h_ct = hashlib.sha256(ct).digest()
    if len(ct) != p.ct_bytes:
        return shake(z + h_ct, 32)  # can never equal a re-encryption
    msg = cpa_decrypt(p, s, ct)
    kc = shake(msg + hashlib.sha256(pk).digest(), 64)
    ok = cpa_encrypt(p, seed_a, b, msg, kc[32:]) == ct
    return shake((kc[:32] if ok else z) + h_ct, 32)
