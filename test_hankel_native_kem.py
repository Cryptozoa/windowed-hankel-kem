#!/usr/bin/env python3
"""Tests of the native Windowed Hankel KEM (hankel_kem_native.c) against the Python reference.

1. KATs: all RESEARCH_v2 vectors through the native API.
2. Equivalence with hankel_kem/fo.py on random inputs: every seed-length branch of key
   generation, several entropy lengths, and decapsulation of valid, tampered, truncated,
   extended and random ciphertexts.
3. Secret kernels against independent NumPy computations, including the all-zero-secret fix-up
   and arbitrary 16-bit inputs to the Hankel product.
4. Malformed keys raise ValueError, as in the reference.
5. Static branch audit of the compiled secret-handling kernels (ct_branch_audit.py).
6. Fixed-vs-random timing (Welch t-test) for key generation, encapsulation and decapsulation.
"""

import ctypes
import os
import sys
import time

import numpy as np

import hankel_kem_core as core
import hankel_kem_wrapper as ref
from hankel_kem import native
from hankel_kem.backends import NATIVE_LIBRARY, NATIVE_LIBRARY_PATH
from nist_analysis_kit.kat.PQCvalidateKAT_hankel import DEFAULT_RSP_PATH, parse_rsp_file
from ct_branch_audit import audit


def test_1_kat():
    vectors = parse_rsp_file(DEFAULT_RSP_PATH)
    assert len(vectors) == 15
    for v in vectors:
        seed, entropy = bytes.fromhex(v["seed"]), bytes.fromhex(v["entropy"])
        pk, sk = native.keygen(seed[:32])
        assert pk.hex().upper() == v["pk"] and sk.hex().upper() == v["sk"], v["count"]
        ct, ss = native.encaps(pk, entropy)
        assert ct.hex().upper() == v["ct"] and ss.hex().upper() == v["ss"], v["count"]
        assert native.decaps(ct, sk) == ss
    print(f"[PASS] 1. Native API reproduces all {len(vectors)} KAT vectors (pk, sk, ct, ss, decapsulation)")


def test_2_equivalence(rounds=6):
    rng = np.random.default_rng(2)
    seed_lengths = (0, 1, 16, 32, 48, 63, 64, 65, 96)
    checked = 0
    for _ in range(rounds):
        for slen in seed_lengths:
            seed = os.urandom(slen)
            pk, sk = native.keygen(seed)
            assert (pk, sk) == ref.hankel_kem_keygen(seed), f"keygen, seed length {slen}"
            for elen in (0, 1, 32, 100):
                entropy = os.urandom(elen)
                ct, ss = native.encaps(pk, entropy)
                assert (ct, ss) == ref.hankel_kem_encaps(pk, entropy), f"encaps, entropy length {elen}"
            assert native.decaps(ct, sk) == ref.hankel_kem_decaps(ct, sk) == ss

            cases = [ct[:-1], ct + b"\x00", b"", ct[:12], os.urandom(len(ct))]
            for pos in rng.integers(0, len(ct), 6):
                bad = bytearray(ct)
                bad[pos] ^= 1 << int(rng.integers(0, 8))
                cases.append(bytes(bad))
            for c in cases:
                got = native.decaps(c, sk)
                assert got == ref.hankel_kem_decaps(c, sk), "decaps of a malformed ciphertext"
                assert got != ss
            checked += 1
    print(f"[PASS] 2. Native output equals the Python reference: {checked} key pairs over seed lengths "
          f"{seed_lengths}, entropy lengths (0, 1, 32, 100), 11 malformed ciphertexts each")


def test_3_kernels(trials=40):
    lib = NATIVE_LIBRARY
    rng = np.random.default_rng(3)
    u16p, s16p = ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_int16)
    lib.hankel_kernel_mul.argtypes = [u16p, u16p, s16p, s16p, ctypes.c_int]
    lib.hankel_kernel_fix_zero_secret.argtypes = [s16p]

    def ptr(a, t):
        return a.ctypes.data_as(t)

    for t in range(trials):
        m = (core.M_LEN, core.W)[t % 2]
        a = rng.integers(0, 1 << 16, m + core.N - 1, dtype=np.uint64).astype(np.uint16)
        x = rng.integers(-32768, 32768, core.N).astype(np.int16)
        e = rng.integers(-32768, 32768, m).astype(np.int16)
        if t % 3 == 0:
            a &= 0x0FFF
            x = rng.integers(-2, 3, core.N).astype(np.int16)
        out = np.zeros(m, dtype=np.uint16)
        use_e = t % 4 != 1
        lib.hankel_kernel_mul(ptr(out, u16p), ptr(a, u16p), ptr(x, s16p),
                              ptr(e, s16p) if use_e else None, m)
        expect = np.array([int(np.dot(a[i:i + core.N].astype(np.int64), x.astype(np.int64)))
                           + (int(e[i]) if use_e else 0) for i in range(m)]) & 0x0FFF
        assert np.array_equal(out, expect.astype(np.uint16)), f"Hankel product, trial {t}"

    s = np.zeros(core.N, dtype=np.int16)
    lib.hankel_kernel_fix_zero_secret(ptr(s, s16p))
    assert s[0] == 1 and not s[1:].any()
    for i in (0, 1, core.N - 1):
        for val in (-2, -1, 1, 2):
            s = np.zeros(core.N, dtype=np.int16)
            s[i] = val
            before = s.copy()
            lib.hankel_kernel_fix_zero_secret(ptr(s, s16p))
            assert np.array_equal(s, before)
    print(f"[PASS] 3. Hankel product kernel matches exact integer dot products ({trials} trials, including "
          "arbitrary 16-bit inputs); all-zero-secret fix-up matches the reference")


def test_4_malformed_keys():
    pk, sk = native.keygen(b"malformed")
    for bad_pk in (pk[:-1], pk + b"\x00", b"XXXX" + pk[4:], pk[:10] + b"\x01\x00" + pk[12:]):
        for f in (native.encaps, ref.hankel_kem_encaps):
            try:
                f(bad_pk, b"e")
            except ValueError:
                pass
            else:
                raise AssertionError("malformed public key accepted")
    ct, _ = native.encaps(pk, b"e")
    for bad_sk in (sk[:-1], sk[:672] + b"XXXX" + sk[676:]):
        for f in (native.decaps, ref.hankel_kem_decaps):
            try:
                f(ct, bad_sk)
            except ValueError:
                pass
            else:
                raise AssertionError("malformed secret key accepted")
    print("[PASS] 4. Malformed public and secret keys raise ValueError in both implementations")


AUDIT_TARGETS = [
    ("_hk_keccakf1600", ("x0",)),
    ("_hankel_kernel_mul", ("x0", "x1", "x2", "x3", "x4")),
    ("_hankel_kernel_cbd2", ("x0", "x1", "x2")),
    ("_hankel_kernel_fix_zero_secret", ("x0",)),
    ("_hankel_kernel_load_secret", ("x0", "x1")),
    ("_hankel_kernel_store_secret", ("x0", "x1")),
    ("_hankel_kernel_encode_add", ("x0", "x1", "x2", "x3")),
    ("_hankel_kernel_decode", ("x0", "x1", "x2")),
    ("_hankel_kernel_verify_select", ("x0", "x1", "x2", "x3", "x4")),
]


def test_5_static_audit():
    total_insns = total_branches = 0
    for sym, public_args in AUDIT_TARGETS:
        n, counts, findings = audit(str(NATIVE_LIBRARY_PATH), sym, public_args, ())
        assert not findings, f"{sym}: {findings}"
        total_insns += n
        total_branches += counts["public_branch"]
    print(f"[PASS] 5. Static audit: {len(AUDIT_TARGETS)} secret-handling functions ({total_insns} instructions), "
          f"{total_branches} branches all on public values, no divisions, no calls")


def _welch(a, b):
    a, b = np.sort(np.asarray(a, float)), np.sort(np.asarray(b, float))
    a, b = a[: int(len(a) * 0.9)], b[: int(len(b) * 0.9)]
    return (a.mean() - b.mean()) / np.sqrt(a.var(ddof=1) / len(a) + b.var(ddof=1) / len(b))


def test_6_timing(samples=4000):
    lib = NATIVE_LIBRARY
    rng = np.random.default_rng(6)
    pk_buf = ctypes.create_string_buffer(native.PK_BYTES)
    sk_buf = ctypes.create_string_buffer(native.SK_BYTES)
    ct_buf = ctypes.create_string_buffer(native.CT_BYTES)
    ss_buf = ctypes.create_string_buffer(32)
    in_buf = ctypes.create_string_buffer(64)

    pk_fixed, sk_fixed = native.keygen(b"\x42" * 64)
    ct_fixed, _ = native.encaps(pk_fixed, b"fixed")
    random_sks = [native.keygen(os.urandom(64))[1] for _ in range(64)]

    def run(name, call, fixed_input, random_input, setup):
        order = rng.integers(0, 2, 2 * samples)
        t_fix, t_rand = [], []
        for i, cls in enumerate(order):
            setup(fixed_input if cls == 0 else random_input(i))  # same buffers in both classes
            t0 = time.perf_counter_ns()
            call()
            dt = time.perf_counter_ns() - t0
            (t_fix if cls == 0 else t_rand).append(dt)
        t = _welch(t_fix, t_rand)
        print(f"[INFO] 6. {name:8s}: fixed {np.median(t_fix)/1e3:6.1f} us, random {np.median(t_rand)/1e3:6.1f} us, "
              f"Welch |t| = {abs(t):.2f}")
        assert abs(t) < 4.5, f"{name}: timing differs between fixed and random secrets"

    def set_in(b):
        ctypes.memmove(in_buf, b, len(b))

    def set_sk(b):
        ctypes.memmove(sk_buf, b, len(b))

    # Key generation: fixed vs random seed.
    run("keygen", lambda: lib.hankel_kem_keypair_derand(pk_buf, sk_buf, in_buf, 64),
        b"\x42" * 64, lambda i: os.urandom(64), set_in)
    # Encapsulation: same public key, fixed vs random message entropy.
    ctypes.memmove(pk_buf, pk_fixed, len(pk_fixed))
    run("encaps", lambda: lib.hankel_kem_enc_derand(ct_buf, ss_buf, pk_buf, in_buf, 32),
        b"\x07" * 32, lambda i: os.urandom(32), set_in)
    # Decapsulation: same ciphertext; the fixed key accepts it, random keys reject it.
    ctypes.memmove(ct_buf, ct_fixed, len(ct_fixed))
    run("decaps", lambda: lib.hankel_kem_dec(ss_buf, ct_buf, native.CT_BYTES, sk_buf),
        sk_fixed, lambda i: random_sks[i % len(random_sks)], set_sk)
    print("[PASS] 6. No first-order timing dependence on secrets detected (|t| < 4.5); "
          "decapsulation takes the same time whether it accepts or rejects")


if __name__ == "__main__":
    if not native.available():
        print(f"Native KEM unavailable; build {NATIVE_LIBRARY_PATH.name} with `make`.")
        sys.exit(1)
    test_1_kat()
    test_2_equivalence()
    test_3_kernels()
    test_4_malformed_keys()
    test_5_static_audit()
    test_6_timing()
    print("NATIVE KEM: ALL CHECKS PASSED")
