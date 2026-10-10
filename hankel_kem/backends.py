"""Explicit arithmetic backends for the same aperiodic Hankel operator.

The convolution backend uses exact int64 arithmetic, not floating-point FFTs.
All backends receive checked integer buffers from operators.py. There is no
fallback after an explicitly selected backend fails.
"""

import ctypes
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

import numpy as np

from . import codec
from .params import Q_MASK, W


class ReferenceBackend:
    name = "reference"

    def forward(self, a, x, n, m, error=None):
        out = np.empty(m, dtype=np.int64)
        for i in range(m):
            out[i] = np.dot(a[i:i + n], x)
        if error is not None:
            out += error
        return out & Q_MASK

    def project(self, x, y, n, w):
        out = np.empty(w, dtype=np.int64)
        for i in range(w):
            out[i] = np.dot(x, y[i:i + n])
        return out & Q_MASK

    def decode(self, noisy, w):
        return codec.decode_message_4pam_256(noisy, w)


class ConvolutionBackend(ReferenceBackend):
    """Exact full convolution followed by the original interior extraction.

NumPy's integer convolution is a candidate implementation, not an NTT and
not a claim of subquadratic complexity or secret-independent execution.
"""

    name = "convolution"

    def forward(self, a, x, n, m, error=None):
        full = np.convolve(a[:n + m - 1], x[::-1])
        out = full[n - 1:n - 1 + m].copy()
        if error is not None:
            out += error
        return out & Q_MASK

    def project(self, x, y, n, w):
        full = np.convolve(y[:n + w], x[::-1])
        return full[n - 1:n - 1 + w] & Q_MASK


class NeonBackend(ReferenceBackend):
    name = "neon"

    def __init__(self, library):
        self.library = library
        u16 = ctypes.POINTER(ctypes.c_uint16)
        s16 = ctypes.POINTER(ctypes.c_int16)
        u8 = ctypes.POINTER(ctypes.c_uint8)
        library.hankel_neon_forward_mul.argtypes = [u16, s16, s16, u16, ctypes.c_int, ctypes.c_int]
        library.hankel_neon_forward_mul.restype = None
        library.hankel_neon_window_project.argtypes = [s16, u16, u16, ctypes.c_int, ctypes.c_int]
        library.hankel_neon_window_project.restype = None
        library.hankel_neon_decode_4pam.argtypes = [u16, u8, ctypes.c_int]
        library.hankel_neon_decode_4pam.restype = None
        self.supports_tails = False
        if hasattr(library, "hankel_neon_supports_tails"):
            library.hankel_neon_supports_tails.argtypes = []
            library.hankel_neon_supports_tails.restype = ctypes.c_int
            self.supports_tails = library.hankel_neon_supports_tails() == 1

    def _check_capacity(self, x, n, error=None):
        if n % 8 and not self.supports_tails:
            raise ValueError("This native library requires n divisible by eight")
        # The compiled dot product uses signed 32-bit accumulators.
        bound = n * Q_MASK * max(abs(int(x.min())), abs(int(x.max())))
        if error is not None:
            bound += max(abs(int(error.min())), abs(int(error.max())))
        if bound > np.iinfo(np.int32).max:
            raise ValueError("Native dot-product accumulator bound exceeds int32")

    def forward(self, a, x, n, m, error=None):
        self._check_capacity(x, n, error)
        a16 = np.ascontiguousarray(a, dtype=np.uint16)
        x16 = np.ascontiguousarray(x, dtype=np.int16)
        out = np.empty(m, dtype=np.uint16)
        e16 = None if error is None else np.ascontiguousarray(error, dtype=np.int16)
        eptr = None if e16 is None else e16.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))
        self.library.hankel_neon_forward_mul(
            a16.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            x16.ctypes.data_as(ctypes.POINTER(ctypes.c_int16)), eptr,
            out.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)), n, m,
        )
        return out.astype(np.int64)

    def project(self, x, y, n, w):
        self._check_capacity(x, n)
        x16 = np.ascontiguousarray(x, dtype=np.int16)
        y16 = np.ascontiguousarray(y, dtype=np.uint16)
        out = np.empty(w, dtype=np.uint16)
        self.library.hankel_neon_window_project(
            x16.ctypes.data_as(ctypes.POINTER(ctypes.c_int16)),
            y16.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            out.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)), n, w,
        )
        return out.astype(np.int64)

    def decode(self, noisy, w):
        if w != W:
            raise ValueError("Native 4-PAM decoder requires the canonical 128 symbols")
        values = np.ascontiguousarray(noisy, dtype=np.uint16)
        out = bytearray(32)
        self.library.hankel_neon_decode_4pam(
            values.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16)),
            (ctypes.c_uint8 * 32).from_buffer(out), w,
        )
        return bytes(out)


# The shared library built by `make`: a .dylib on macOS, a .so elsewhere.
NATIVE_LIBRARY_NAME = "libhankel_kem_neon." + ("dylib" if sys.platform == "darwin" else "so")
NATIVE_LIBRARY_PATH = Path(__file__).resolve().parents[1] / NATIVE_LIBRARY_NAME
NATIVE_LIBRARY = None
NATIVE_LOAD_ERROR = None
_BACKENDS = {"reference": ReferenceBackend(), "convolution": ConvolutionBackend()}
try:
    if NATIVE_LIBRARY_PATH.exists():
        library = ctypes.CDLL(str(NATIVE_LIBRARY_PATH))
        native = NeonBackend(library)
        NATIVE_LIBRARY = library
        _BACKENDS["neon"] = native
    else:
        NATIVE_LOAD_ERROR = "Native library file is absent"
except (OSError, AttributeError) as exc:
    NATIVE_LOAD_ERROR = str(exc)

_SELECTED = ContextVar("hankel_backend", default="auto")


def available_backends():
    return tuple(_BACKENDS)


def configured_backend():
    return _SELECTED.get()


def resolve_backend(name=None):
    name = configured_backend() if name is None else name
    if name == "auto":
        name = "neon" if "neon" in _BACKENDS else "reference"
    if name not in _BACKENDS:
        if name == "neon":
            raise RuntimeError(f"Native Hankel backend unavailable: {NATIVE_LOAD_ERROR}")
        raise ValueError(f"Unknown Hankel backend: {name!r}")
    return _BACKENDS[name]


def get_backend_name():
    return resolve_backend().name


@contextmanager
def use_backend(name):
    """Select a backend for this context; restore it even when a call fails."""
    resolve_backend(name)
    token = _SELECTED.set(name)
    try:
        yield resolve_backend(name)
    finally:
        _SELECTED.reset(token)
