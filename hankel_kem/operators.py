"""Checked forward and projection operations for the canonical modulus.

Dimensions of research primitive calls may differ from the frozen wire profile.
Backend capabilities are enforced before exposing pointers to native code.
"""

import operator

import numpy as np

from .backends import resolve_backend
from .params import N, M_LEN, W, Q_MASK


def _dimension(value, name):
    try:
        value = operator.index(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be an integer dimension") from exc
    if value <= 0 or value > np.iinfo(np.int32).max:
        raise ValueError(f"{name} must be positive and fit int32")
    return value


def _array(value, name, *, length, exact=False, field=False, small=False):
    if type(value) is not np.ndarray or value.dtype.kind not in ("i", "u"):
        raise TypeError(f"{name} must be an exact ndarray with integer dtype")
    if value.ndim != 1 or (len(value) != length if exact else len(value) < length):
        raise ValueError(f"{name} has an incompatible one-dimensional length")
    value = value[:length]
    low, high = int(value.min()), int(value.max())
    if field and (low < 0 or high > Q_MASK):
        raise ValueError(f"{name} must contain canonical coefficients 0..4095")
    if small and (low < -32768 or high > 32767):
        raise ValueError(f"{name} must fit signed int16")
    return np.ascontiguousarray(value, dtype=np.int64)


def hankel_forward_multiply(a_seq, x, n=N, m=M_LEN, *, backend=None, error=None):
    n, m = _dimension(n, "n"), _dimension(m, "m")
    a = _array(a_seq, "a_seq", length=n + m - 1, field=True)
    secret = _array(x, "x", length=n, exact=True, small=True)
    e = None if error is None else _array(error, "error", length=m, exact=True, small=True)
    # Given the accepted scalar ranges and int32 dimensions, int64 convolution
    # is exact even for every full-product coefficient, not only the slice.
    if n * Q_MASK * 32768 + 32768 > np.iinfo(np.int64).max:
        raise ValueError("Integer convolution accumulator exceeds int64")
    return resolve_backend(backend).forward(a, secret, n, m, error=e)


def hankel_window_project(x, y_ext, n=N, w_len=W, *, backend=None):
    n, w = _dimension(n, "n"), _dimension(w_len, "w_len")
    secret = _array(x, "x", length=n, exact=True, small=True)
    # Preserve the original public buffer contract (including its last unused
    # coefficient) and extract precisely the same w output coordinates.
    y = _array(y_ext, "y_ext", length=n + w, field=True)
    if n * Q_MASK * 32768 > np.iinfo(np.int64).max:
        raise ValueError("Integer projection accumulator exceeds int64")
    return resolve_backend(backend).project(secret, y, n, w)


def decode_message_4pam_256(noisy_vector, window_size=W, *, backend=None):
    if window_size != W:
        raise ValueError("The canonical 256-bit message requires 128 symbols")
    values = _array(noisy_vector, "noisy_vector", length=W, exact=True, field=True)
    return resolve_backend(backend).decode(values, W)
