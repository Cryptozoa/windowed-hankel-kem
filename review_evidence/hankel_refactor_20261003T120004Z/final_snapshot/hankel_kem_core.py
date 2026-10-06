"""Compatibility API for the frozen Windowed Hankel research construction.

Select explicit arithmetic with use_backend("reference"/"neon"/"convolution")
or a backend keyword. "auto" retains the original native-if-present default.
Explicit backends never silently switch implementations after failure.
"""
import os
import math
import hashlib
import ctypes
from typing import Optional, Tuple
import numpy as np

from hankel_kem.params import (Q, Q_MASK, ETA, N, W, M_LEN, TOTAL_A_LEN,
    PAM_POINTS, DECISION_THRESHOLD, PK_BYTES, CT_BYTES, SK_BYTES, CANONICAL)
from hankel_kem.sampling import expand_public_sequence_a, sample_cbd2_from_bytes
from hankel_kem.codec import pack_12bit, unpack_12bit, encode_message_4pam_256
from hankel_kem.backends import (available_backends, use_backend, get_backend_name,
    configured_backend, NATIVE_LIBRARY, NATIVE_LOAD_ERROR)
from hankel_kem import operators, cpa

# Retained only for old callers that explicitly disable the native library.
_C_LIB = NATIVE_LIBRARY


def _effective_backend(backend):
    if backend is not None:
        return backend
    selected = configured_backend()
    if selected != "auto":
        return selected
    return "neon" if _C_LIB is not None else "reference"


def is_native_loaded():
    return NATIVE_LIBRARY is not None and _C_LIB is not None


def hankel_forward_multiply(a_seq, x, n=N, m=M_LEN, *, backend=None, error=None):
    return operators.hankel_forward_multiply(a_seq, x, n, m,
        backend=_effective_backend(backend), error=error)


def hankel_window_project(x, y_ext, n=N, w_len=W, *, backend=None):
    return operators.hankel_window_project(x, y_ext, n, w_len,
        backend=_effective_backend(backend))


def decode_message_4pam_256(noisy_vector, window_size=W, *, backend=None):
    return operators.decode_message_4pam_256(noisy_vector, window_size,
        backend=_effective_backend(backend))


def hankel_kem_cpa_keygen(seed=None, n=N, w_len=W, *, backend=None):
    return cpa.hankel_kem_cpa_keygen(seed, n, w_len,
        backend=_effective_backend(backend), sampler=sample_cbd2_from_bytes,
        expander=expand_public_sequence_a)


def hankel_kem_cpa_encaps(seed_a, b, msg, coins, n=N, w_len=W, *, backend=None):
    return cpa.hankel_kem_cpa_encaps(seed_a, b, msg, coins, n, w_len,
        backend=_effective_backend(backend), sampler=sample_cbd2_from_bytes,
        expander=expand_public_sequence_a)


def hankel_kem_cpa_decaps(s, u, v, n=N, w_len=W, *, backend=None):
    return cpa.hankel_kem_cpa_decaps(s, u, v, n, w_len,
        backend=_effective_backend(backend))
