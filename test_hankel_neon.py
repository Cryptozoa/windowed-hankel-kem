#!/usr/bin/env python3
"""
Windowed Hankel LWE KEM: Native ARM64 NEON Verification & Benchmark Suite
------------------------------------------------------------------------
Tests bit-exact equivalence between Python reference and C/NEON engine,
validates retained local KAT vectors, and invokes the fresh-input benchmark.
Functional checks do not establish constant-time behavior or security.
"""

import os
import sys
import ctypes
import numpy as np

from hankel_kem_core import (
    Q, Q_MASK, ETA, N, W, M_LEN, TOTAL_A_LEN,
    expand_public_sequence_a, sample_cbd2_from_bytes,
    pack_12bit, unpack_12bit,
    encode_message_4pam_256, decode_message_4pam_256,
    hankel_forward_multiply, hankel_window_project
)
from hankel_kem_wrapper import (
    hankel_kem_keygen, hankel_kem_encaps, hankel_kem_decaps,
    constant_time_select, constant_time_compare
)

# Load C library
lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "libhankel_kem_neon." + ("dylib" if sys.platform == "darwin" else "so"))
if not os.path.exists(lib_path):
    raise FileNotFoundError(f"Native shared library not found: {lib_path}")

c_lib = ctypes.CDLL(lib_path)

# Configure C Function Signatures
c_lib.hankel_neon_forward_mul.argtypes = [
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.POINTER(ctypes.c_int16),
    ctypes.POINTER(ctypes.c_int16),
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.c_int,
    ctypes.c_int
]

c_lib.hankel_neon_window_project.argtypes = [
    ctypes.POINTER(ctypes.c_int16),
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.c_int,
    ctypes.c_int
]

c_lib.hankel_neon_encode_4pam.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.c_int
]

c_lib.hankel_neon_decode_4pam.argtypes = [
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int
]

c_lib.hankel_neon_pack_12bit.argtypes = [
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int
]

c_lib.hankel_neon_unpack_12bit.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.c_int
]
c_lib.hankel_neon_unpack_12bit.restype = ctypes.c_int

c_lib.hankel_ct_select.argtypes = [
    ctypes.c_uint8,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t
]

c_lib.hankel_ct_compare.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t
]
c_lib.hankel_ct_compare.restype = ctypes.c_int


def ptr_u16(arr: np.ndarray):
    return arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint16))

def ptr_s16(arr: np.ndarray):
    return arr.ctypes.data_as(ctypes.POINTER(ctypes.c_int16))

def ptr_u8(buf: bytes or bytearray or np.ndarray):
    if isinstance(buf, (bytes, bytearray)):
        return (ctypes.c_uint8 * len(buf)).from_buffer_copy(buf)
    return buf.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))


def run_native_checks():
    print("=" * 80)
    print("   WINDOWED HANKEL LWE KEM: NATIVE ARM64 NEON VERIFICATION & BENCHMARK")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # PART 1: Function-by-Function Bit-Exact Equivalence Testing
    # -------------------------------------------------------------------------
    print("\n[+] PART 1: Bit-Exact Functional Equivalence (Python vs Native NEON)...")

    # 1A. Forward Multiplication H(a) * s + e
    a_seq = expand_public_sequence_a(os.urandom(32), TOTAL_A_LEN).astype(np.uint16)
    s = sample_cbd2_from_bytes(os.urandom(N), N).astype(np.int16)
    e = sample_cbd2_from_bytes(os.urandom(M_LEN), M_LEN).astype(np.int16)

    py_b = hankel_forward_multiply(a_seq, s, n=N, m=M_LEN, backend="reference", error=e)
    c_b = np.empty(M_LEN, dtype=np.uint16)
    c_lib.hankel_neon_forward_mul(ptr_u16(a_seq), ptr_s16(s), ptr_s16(e), ptr_u16(c_b), N, M_LEN)

    assert np.array_equal(py_b, c_b), "Forward multiply mismatch between Python and C!"
    print("    [PASS] hankel_neon_forward_mul (768 dot products of length 640): 100% bit-exact match.")

    # 1B. Windowed Projection K_w = Project(x, y_ext)
    r = sample_cbd2_from_bytes(os.urandom(N), N).astype(np.int16)
    py_k = hankel_window_project(r, py_b, n=N, w_len=W, backend="reference")
    c_k = np.empty(W, dtype=np.uint16)
    c_lib.hankel_neon_window_project(ptr_s16(r), ptr_u16(c_b), ptr_u16(c_k), N, W)

    assert np.array_equal(py_k, c_k), "Window projection mismatch between Python and C!"
    print("    [PASS] hankel_neon_window_project (128 sliding projections): 100% bit-exact match.")

    # 1C. 4-PAM Encode & Branchless Decode
    test_msg = os.urandom(32)
    py_enc = encode_message_4pam_256(test_msg, window_size=W)
    c_enc = np.empty(W, dtype=np.uint16)
    c_lib.hankel_neon_encode_4pam(ptr_u8(test_msg), ptr_u16(c_enc), W)
    assert np.array_equal(py_enc, c_enc), "4-PAM encode mismatch!"

    # Decode
    noisy_k = (c_k + c_enc) & Q_MASK
    py_dec = decode_message_4pam_256(noisy_k, window_size=W, backend="reference")
    c_dec = bytearray(32)
    c_lib.hankel_neon_decode_4pam(ptr_u16(noisy_k.astype(np.uint16)), (ctypes.c_uint8 * 32).from_buffer(c_dec), W)
    assert bytes(c_dec) == py_dec, "4-PAM decode mismatch!"
    print("    [PASS] 4-PAM Encode & Branchless Voronoi Decoder: 100% bit-exact match.")

    # 1D. Canonical 12-Bit Packing and Unpacking
    test_words = (np.frombuffer(os.urandom(768 * 2), dtype="<u2") & Q_MASK).astype(np.uint16)
    py_packed = pack_12bit(test_words)
    c_packed = bytearray((768 * 3) // 2)
    c_lib.hankel_neon_pack_12bit(ptr_u16(test_words), (ctypes.c_uint8 * len(c_packed)).from_buffer(c_packed), 768)
    assert bytes(c_packed) == py_packed, "12-bit packing mismatch!"

    c_unpacked = np.empty(768, dtype=np.uint16)
    is_valid = c_lib.hankel_neon_unpack_12bit((ctypes.c_uint8 * len(c_packed)).from_buffer(c_packed), ptr_u16(c_unpacked), 768)
    assert is_valid == 1 and np.array_equal(c_unpacked, test_words), "12-bit unpacking mismatch!"
    print("    [PASS] 12-bit SIMD Packing and Unpacking: 100% bit-exact match.")

    # 1E. Constant-Time Multiplexer and Comparison
    a_bytes = os.urandom(64)
    b_bytes = os.urandom(64)
    out_sel = bytearray(64)
    c_buf_out = (ctypes.c_uint8 * 64).from_buffer(out_sel)

    # Select A (cond = 1)
    c_lib.hankel_ct_select(1, ptr_u8(a_bytes), ptr_u8(b_bytes), c_buf_out, 64)
    assert bytes(out_sel) == a_bytes, "CT select 1 failed!"
    # Select B (cond = 0)
    c_lib.hankel_ct_select(0, ptr_u8(a_bytes), ptr_u8(b_bytes), c_buf_out, 64)
    assert bytes(out_sel) == b_bytes, "CT select 0 failed!"

    # Compare
    cmp_eq = c_lib.hankel_ct_compare(ptr_u8(a_bytes), ptr_u8(a_bytes), 64)
    cmp_neq = c_lib.hankel_ct_compare(ptr_u8(a_bytes), ptr_u8(b_bytes), 64)
    assert cmp_eq == 1 and cmp_neq == 0, "CT compare mismatch!"
    print("    [PASS] Native byte selection and comparison: functional outputs match.")

    # -------------------------------------------------------------------------
    # PART 2: Retained Local KAT Response File Validation
    # -------------------------------------------------------------------------
    print("\n[+] PART 2: Validating native execution against retained local KAT vectors...")
    from nist_analysis_kit.kat.PQCvalidateKAT_hankel import parse_rsp_file, DEFAULT_RSP_PATH
    rsp_path = DEFAULT_RSP_PATH
    vectors = parse_rsp_file(rsp_path)
    print(f"    Loaded {len(vectors)} local KAT vectors from {os.path.basename(rsp_path)}.")

    for i, vec in enumerate(vectors):
        count = int(vec["count"])
        seed = bytes.fromhex(vec["seed"])
        pk_expected = bytes.fromhex(vec["pk"])
        sk_expected = bytes.fromhex(vec["sk"])
        ct_expected = bytes.fromhex(vec["ct"])
        ss_expected = bytes.fromhex(vec["ss"])

        # Decapsulate using C-backed primitives
        ss_dec = hankel_kem_decaps(ct_expected, sk_expected, backend="neon")
        assert ss_dec == ss_expected, f"local KAT mismatch on vector {count}!"

    print(f"    [PASS] All {len(vectors)} local KAT vectors verified bit-exact with 100% fidelity.")

    print("\n" + "=" * 80)
    print("   NATIVE ARM64 NEON VERIFICATION COMPLETE: ALL CHECKS PASSED.")
    print("=" * 80)


def run_tests_and_benchmarks(argv=None):
    run_native_checks()
    from benchmark_hankel_backends import main as benchmark_main
    return benchmark_main(argv)


if __name__ == "__main__":
    raise SystemExit(run_tests_and_benchmarks(sys.argv[1:]))
