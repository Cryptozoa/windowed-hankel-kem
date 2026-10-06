"""Compatibility exports for the existing Hankel KEM wire and FO interfaces.

The canonical profile, serialized bytes and derivation tags remain unchanged.
KEM functions accept an optional keyword-only backend for explicit selection.
"""

# Keep the legacy public constants and CPA helpers available to existing callers.
from hankel_kem_core import (
    Q, Q_MASK, ETA, N, W, M_LEN, TOTAL_A_LEN,
    pack_12bit, unpack_12bit,
    hankel_kem_cpa_keygen, hankel_kem_cpa_encaps, hankel_kem_cpa_decaps,
)
from hankel_kem.wire import (
    MAGIC_PK, MAGIC_CT,
    HankelKEMPublicKey, HankelKEMSecretKey,
    serialize_public_key, deserialize_public_key,
    serialize_ciphertext, deserialize_ciphertext,
)
from hankel_kem.fo import (
    constant_time_select, constant_time_compare,
    hankel_kem_keygen, hankel_kem_encaps, hankel_kem_decaps,
)

__all__ = [
    "Q", "Q_MASK", "ETA", "N", "W", "M_LEN", "TOTAL_A_LEN",
    "pack_12bit", "unpack_12bit",
    "hankel_kem_cpa_keygen", "hankel_kem_cpa_encaps", "hankel_kem_cpa_decaps",
    "MAGIC_PK", "MAGIC_CT", "HankelKEMPublicKey", "HankelKEMSecretKey",
    "serialize_public_key", "deserialize_public_key",
    "serialize_ciphertext", "deserialize_ciphertext",
    "constant_time_select", "constant_time_compare",
    "hankel_kem_keygen", "hankel_kem_encaps", "hankel_kem_decaps",
]
