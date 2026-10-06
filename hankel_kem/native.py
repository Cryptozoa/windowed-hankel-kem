"""ctypes bindings for the native Windowed Hankel KEM (hankel_kem_native.c).

The native functions take the same inputs and produce the same bytes as hankel_kem/fo.py:
keygen(seed) as hankel_kem_keygen(seed), encaps(pk, entropy) as hankel_kem_encaps(pk, entropy)
and decaps(ct, sk) as hankel_kem_decaps(ct, sk). They raise ValueError where the reference
raises on a malformed public or secret key.
"""

import ctypes
from typing import Optional, Tuple

from .backends import NATIVE_LIBRARY
from .params import CT_BYTES, PK_BYTES, SK_BYTES

SS_BYTES = 32


def _bind(library):
    if library is None or not hasattr(library, "hankel_kem_dec"):
        return None
    c = ctypes
    u8p, size = c.c_char_p, c.c_size_t
    library.hankel_kem_keypair.argtypes = [c.c_void_p, c.c_void_p]
    library.hankel_kem_keypair_derand.argtypes = [c.c_void_p, c.c_void_p, u8p, size]
    library.hankel_kem_enc.argtypes = [c.c_void_p, c.c_void_p, u8p]
    library.hankel_kem_enc_derand.argtypes = [c.c_void_p, c.c_void_p, u8p, u8p, size]
    library.hankel_kem_dec.argtypes = [c.c_void_p, u8p, size, u8p]
    for name in ("hankel_kem_keypair", "hankel_kem_keypair_derand", "hankel_kem_enc",
                 "hankel_kem_enc_derand", "hankel_kem_dec"):
        getattr(library, name).restype = c.c_int
    return library


_LIB = _bind(NATIVE_LIBRARY)


def available() -> bool:
    return _LIB is not None


def _require():
    if _LIB is None:
        raise RuntimeError("Native KEM unavailable: build libhankel_kem_neon.dylib with `make`")
    return _LIB


def keygen(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    lib = _require()
    pk = ctypes.create_string_buffer(PK_BYTES)
    sk = ctypes.create_string_buffer(SK_BYTES)
    if seed is None:
        rc = lib.hankel_kem_keypair(pk, sk)
    else:
        seed = bytes(seed)
        rc = lib.hankel_kem_keypair_derand(pk, sk, seed, len(seed))
    if rc != 0:
        raise RuntimeError("native key generation failed")
    return pk.raw, sk.raw


def encaps(pk: bytes, entropy: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    lib = _require()
    pk = bytes(pk)
    if len(pk) != PK_BYTES:
        raise ValueError(f"Public key length mismatch: expected {PK_BYTES}, got {len(pk)}")
    ct = ctypes.create_string_buffer(CT_BYTES)
    ss = ctypes.create_string_buffer(SS_BYTES)
    if entropy is None:
        rc = lib.hankel_kem_enc(ct, ss, pk)
    else:
        entropy = bytes(entropy)
        rc = lib.hankel_kem_enc_derand(ct, ss, pk, entropy, len(entropy))
    if rc != 0:
        raise ValueError("Malformed public key header")
    return ct.raw, ss.raw


def decaps(ct: bytes, sk: bytes) -> bytes:
    lib = _require()
    sk, ct = bytes(sk), bytes(ct)
    if len(sk) != SK_BYTES:
        raise ValueError(f"Secret key length mismatch: expected {SK_BYTES}, got {len(sk)}")
    ss = ctypes.create_string_buffer(SS_BYTES)
    if lib.hankel_kem_dec(ss, ct, len(ct), sk) != 0:
        raise ValueError("Malformed public key header inside the secret key")
    return ss.raw
