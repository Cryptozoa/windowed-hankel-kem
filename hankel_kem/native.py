"""ctypes bindings for the native Windowed Hankel KEM (hankel_kem_native.c), all parameter sets.

The native functions take the same inputs and produce the same bytes as the Python references:
for WH-640, hankel_kem/fo.py (hankel_kem_keygen, hankel_kem_encaps, hankel_kem_decaps); for every
set, hankel_kem/generic.py. They raise ValueError where the reference raises on a malformed public
or secret key. Select the set with profile="WH-640" (default), "WH-936" or "WH-1208".
"""

import ctypes
from typing import Optional, Tuple

from .backends import NATIVE_LIBRARY
from .generic import PROFILES

SS_BYTES = 32
PREFIX = {"WH-640": "hankel_", "WH-936": "hankel936_", "WH-1208": "hankel1208_"}
# Sizes of the default set, kept for existing callers.
PK_BYTES, CT_BYTES, SK_BYTES = (PROFILES["WH-640"].pk_bytes, PROFILES["WH-640"].ct_bytes,
                                PROFILES["WH-640"].sk_bytes)


def _bind(library):
    if library is None:
        return None
    c = ctypes
    u8p, size = c.c_char_p, c.c_size_t
    bound = {}
    for name, pfx in PREFIX.items():
        try:
            fns = {op: getattr(library, f"{pfx}kem_{op}") for op in
                   ("keypair", "keypair_derand", "enc", "enc_derand", "dec")}
        except AttributeError:
            continue
        fns["keypair"].argtypes = [c.c_void_p, c.c_void_p]
        fns["keypair_derand"].argtypes = [c.c_void_p, c.c_void_p, u8p, size]
        fns["enc"].argtypes = [c.c_void_p, c.c_void_p, u8p]
        fns["enc_derand"].argtypes = [c.c_void_p, c.c_void_p, u8p, u8p, size]
        fns["dec"].argtypes = [c.c_void_p, u8p, size, u8p]
        for f in fns.values():
            f.restype = c.c_int
        bound[name] = fns
    return bound or None


_LIB = _bind(NATIVE_LIBRARY)


def available(profile: str = "WH-640") -> bool:
    return _LIB is not None and profile in _LIB


def _require(profile: str):
    if profile not in PROFILES:
        raise ValueError(f"Unknown parameter set {profile!r}; choose from {sorted(PROFILES)}")
    if not available(profile):
        raise RuntimeError("Native KEM unavailable: build libhankel_kem_neon.dylib with `make`")
    return _LIB[profile], PROFILES[profile]


def keygen(seed: Optional[bytes] = None, profile: str = "WH-640") -> Tuple[bytes, bytes]:
    fns, p = _require(profile)
    pk = ctypes.create_string_buffer(p.pk_bytes)
    sk = ctypes.create_string_buffer(p.sk_bytes)
    if seed is None:
        rc = fns["keypair"](pk, sk)
    else:
        seed = bytes(seed)
        rc = fns["keypair_derand"](pk, sk, seed, len(seed))
    if rc != 0:
        raise RuntimeError("native key generation failed")
    return pk.raw, sk.raw


def encaps(pk: bytes, entropy: Optional[bytes] = None, profile: str = "WH-640") -> Tuple[bytes, bytes]:
    fns, p = _require(profile)
    pk = bytes(pk)
    if len(pk) != p.pk_bytes:
        raise ValueError(f"Public key length mismatch: expected {p.pk_bytes}, got {len(pk)}")
    ct = ctypes.create_string_buffer(p.ct_bytes)
    ss = ctypes.create_string_buffer(SS_BYTES)
    if entropy is None:
        rc = fns["enc"](ct, ss, pk)
    else:
        entropy = bytes(entropy)
        rc = fns["enc_derand"](ct, ss, pk, entropy, len(entropy))
    if rc != 0:
        raise ValueError("Malformed public key header")
    return ct.raw, ss.raw


def decaps(ct: bytes, sk: bytes, profile: str = "WH-640") -> bytes:
    fns, p = _require(profile)
    sk, ct = bytes(sk), bytes(ct)
    if len(sk) != p.sk_bytes:
        raise ValueError(f"Secret key length mismatch: expected {p.sk_bytes}, got {len(sk)}")
    ss = ctypes.create_string_buffer(SS_BYTES)
    if fns["dec"](ss, ct, len(ct), sk) != 0:
        raise ValueError("Malformed public key header inside the secret key")
    return ss.raw
