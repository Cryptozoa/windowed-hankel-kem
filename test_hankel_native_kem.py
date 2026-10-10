#!/usr/bin/env python3
"""Tests of the native Windowed Hankel KEM (hankel_kem_native.c) against the Python references.

Every test runs for each parameter set: WH-640 (reference hankel_kem/fo.py, KAT file
RESEARCH_v2) and the candidate Category 3 and 5 sets WH-936 and WH-1208 (reference
hankel_kem/generic.py, KAT files WINDOWED_HANKEL_{936,1208}_v1).

1. KATs: all vectors through the native API.
2. Equivalence with the reference on random inputs: every seed-length branch of key
   generation, several entropy lengths, and decapsulation of valid, tampered, truncated,
   extended and random ciphertexts. For WH-640 the generic reference is also checked against fo.py.
3. Secret kernels against independent NumPy computations, including the all-zero-secret fix-up
   and arbitrary 16-bit inputs to the Hankel product.
4. Malformed keys raise ValueError, as in the reference.
5. Static branch audit of the compiled secret-handling kernels (ct_branch_audit.py).
6. Fixed-vs-random timing (Welch t-test) for key generation, encapsulation and decapsulation.
"""

import ctypes
import os
import platform
import sys
import time

import numpy as np

import hankel_kem_wrapper as ref
from hankel_kem import generic, native
from hankel_kem.backends import NATIVE_LIBRARY, NATIVE_LIBRARY_PATH
from nist_analysis_kit.kat import PQCgenKAT_hankel_sets as kat_sets
from nist_analysis_kit.kat.PQCvalidateKAT_hankel import DEFAULT_RSP_PATH, parse_rsp_file
from ct_branch_audit import audit

SETS = ("WH-640", "WH-936", "WH-1208")


def reference(name):
    """(keygen, encaps, decaps) of the Python reference for a set."""
    if name == "WH-640":
        return ref.hankel_kem_keygen, ref.hankel_kem_encaps, ref.hankel_kem_decaps
    p = generic.PROFILES[name]
    return (lambda seed: generic.keygen(p, seed), lambda pk, e: generic.encaps(p, pk, e),
            lambda ct, sk: generic.decaps(p, ct, sk))


def kat_vectors(name):
    if name == "WH-640":
        return parse_rsp_file(DEFAULT_RSP_PATH)
    return kat_sets.parse(os.path.join(kat_sets.OUT_DIR, kat_sets.SETS[name] + ".rsp"))


def test_1_kat():
    for name in SETS:
        vectors = kat_vectors(name)
        assert len(vectors) == 15
        for v in vectors:
            seed, entropy = bytes.fromhex(v["seed"]), bytes.fromhex(v["entropy"])
            pk, sk = native.keygen(seed[:32], name)
            assert pk.hex().upper() == v["pk"] and sk.hex().upper() == v["sk"], (name, v["count"])
            ct, ss = native.encaps(pk, entropy, name)
            assert ct.hex().upper() == v["ct"] and ss.hex().upper() == v["ss"], (name, v["count"])
            assert native.decaps(ct, sk, name) == ss
    print(f"[PASS] 1. Native API reproduces all KAT vectors of {', '.join(SETS)} "
          "(15 each; pk, sk, ct, ss, decapsulation)")


def test_2_equivalence(rounds=6):
    rng = np.random.default_rng(2)
    seed_lengths = (0, 1, 16, 32, 48, 63, 64, 65, 96)
    for name in SETS:
        r_keygen, r_encaps, r_decaps = reference(name)
        checked = 0
        for _ in range(rounds if name == "WH-640" else 2):
            for slen in seed_lengths:
                seed = os.urandom(slen)
                pk, sk = native.keygen(seed, name)
                assert (pk, sk) == r_keygen(seed), f"{name} keygen, seed length {slen}"
                if name == "WH-640":
                    assert (pk, sk) == generic.keygen(generic.WH640, seed), "generic WH-640 keygen"
                for elen in (0, 1, 32, 100):
                    entropy = os.urandom(elen)
                    ct, ss = native.encaps(pk, entropy, name)
                    assert (ct, ss) == r_encaps(pk, entropy), f"{name} encaps, entropy length {elen}"
                assert native.decaps(ct, sk, name) == r_decaps(ct, sk) == ss

                cases = [ct[:-1], ct + b"\x00", b"", ct[:12], os.urandom(len(ct))]
                for pos in rng.integers(0, len(ct), 6):
                    bad = bytearray(ct)
                    bad[pos] ^= 1 << int(rng.integers(0, 8))
                    cases.append(bytes(bad))
                for c in cases:
                    got = native.decaps(c, sk, name)
                    assert got == r_decaps(c, sk), f"{name} decaps of a malformed ciphertext"
                    assert got != ss
                checked += 1
        print(f"[PASS] 2. {name}: native output equals the Python reference on {checked} key pairs over "
              f"seed lengths {seed_lengths}, entropy lengths (0, 1, 32, 100), 11 malformed ciphertexts each")


def test_3_kernels(trials=40):
    lib = NATIVE_LIBRARY
    rng = np.random.default_rng(3)
    u16p, s16p = ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_int16)

    def ptr(a, t):
        return a.ctypes.data_as(t)

    for name in SETS:
        p, pfx = generic.PROFILES[name], native.PREFIX[name]
        mul, fix = getattr(lib, f"{pfx}kernel_mul"), getattr(lib, f"{pfx}kernel_fix_zero_secret")
        mul.argtypes = [u16p, u16p, s16p, s16p, ctypes.c_int]
        fix.argtypes = [s16p]
        n = p.n
        for t in range(trials):
            m = (p.m, p.w)[t % 2]
            a = rng.integers(0, 1 << 16, m + n - 1, dtype=np.uint64).astype(np.uint16)
            x = rng.integers(-32768, 32768, n).astype(np.int16)
            e = rng.integers(-32768, 32768, m).astype(np.int16)
            if t % 3 == 0:
                a &= p.mask
                x = rng.integers(-2, 3, n).astype(np.int16)
            out = np.zeros(m, dtype=np.uint16)
            use_e = t % 4 != 1
            mul(ptr(out, u16p), ptr(a, u16p), ptr(x, s16p), ptr(e, s16p) if use_e else None, m)
            expect = np.array([int(np.dot(a[i:i + n].astype(np.int64), x.astype(np.int64)))
                               + (int(e[i]) if use_e else 0) for i in range(m)]) & p.mask
            assert np.array_equal(out, expect.astype(np.uint16)), f"{name} Hankel product, trial {t}"

        s = np.zeros(n, dtype=np.int16)
        fix(ptr(s, s16p))
        assert s[0] == 1 and not s[1:].any()
        for i in (0, 1, n - 1):
            for val in (-2, -1, 1, 2):
                s = np.zeros(n, dtype=np.int16)
                s[i] = val
                before = s.copy()
                fix(ptr(s, s16p))
                assert np.array_equal(s, before)
    print(f"[PASS] 3. Hankel product kernels of all sets match exact integer dot products ({trials} trials "
          "each, including arbitrary 16-bit inputs); all-zero-secret fix-up matches the reference")


def test_4_malformed_keys():
    for name in SETS:
        _, r_encaps, r_decaps = reference(name)
        n = generic.PROFILES[name].n
        pk, sk = native.keygen(b"malformed", name)
        for bad_pk in (pk[:-1], pk + b"\x00", b"XXXX" + pk[4:], pk[:10] + b"\x01\x00" + pk[12:]):
            for f in (lambda k, e: native.encaps(k, e, name), r_encaps):
                try:
                    f(bad_pk, b"e")
                except ValueError:
                    pass
                else:
                    raise AssertionError(f"{name}: malformed public key accepted")
        ct, _ = native.encaps(pk, b"e", name)
        # sk = s (n bytes) || z (32) || pk; corrupt the length, then the embedded pk magic.
        for bad_sk in (sk[:-1], sk[:n + 32] + b"XXXX" + sk[n + 36:]):
            for f in (lambda c, k: native.decaps(c, k, name), r_decaps):
                try:
                    f(ct, bad_sk)
                except ValueError:
                    pass
                else:
                    raise AssertionError(f"{name}: malformed secret key accepted")
    print("[PASS] 4. Malformed public and secret keys raise ValueError in both implementations, all sets")


KERNEL_ARGS = [
    ("kernel_mul", ("x0", "x1", "x2", "x3", "x4")),
    ("kernel_cbd2", ("x0", "x1", "x2")),
    ("kernel_fix_zero_secret", ("x0",)),
    ("kernel_load_secret", ("x0", "x1")),
    ("kernel_store_secret", ("x0", "x1")),
    ("kernel_encode_add", ("x0", "x1", "x2", "x3")),
    ("kernel_decode", ("x0", "x1", "x2")),
    ("kernel_verify_select", ("x0", "x1", "x2", "x3", "x4")),
]
AUDIT_TARGETS = [("_hk_keccakf1600", ("x0",))] + [
    (f"_{native.PREFIX[name]}{k}", args) for name in SETS for k, args in KERNEL_ARGS]


def test_5_static_audit():
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("[SKIP] 5. Static audit: needs otool and an ARM64 Mach-O library (macOS on Apple Silicon); "
              "the recorded results are in review_evidence/hankel_native_sets_20261007T164709Z/")
        return
    total_insns = total_branches = 0
    for sym, public_args in AUDIT_TARGETS:
        n, counts, findings = audit(str(NATIVE_LIBRARY_PATH), sym, public_args, ())
        assert not findings, f"{sym}: {findings}"
        total_insns += n
        total_branches += counts["public_branch"]
    print(f"[PASS] 5. Static audit: {len(AUDIT_TARGETS)} secret-handling functions over all sets "
          f"({total_insns} instructions), "
          f"{total_branches} branches all on public values, no divisions, no calls")


def _welch(a, b):
    a, b = np.sort(np.asarray(a, float)), np.sort(np.asarray(b, float))
    a, b = a[: int(len(a) * 0.9)], b[: int(len(b) * 0.9)]
    return (a.mean() - b.mean()) / np.sqrt(a.var(ddof=1) / len(a) + b.var(ddof=1) / len(b))


def test_6_timing(samples=4000):
    lib = NATIVE_LIBRARY
    rng = np.random.default_rng(6)

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
        print(f"[INFO] 6. {name:16s}: fixed {np.median(t_fix)/1e3:6.1f} us, random {np.median(t_rand)/1e3:6.1f} us, "
              f"Welch |t| = {abs(t):.2f}")
        assert abs(t) < 4.5, f"{name}: timing differs between fixed and random secrets"

    for name in SETS:
        p, pfx = generic.PROFILES[name], native.PREFIX[name]
        keypair_derand = getattr(lib, f"{pfx}kem_keypair_derand")
        enc_derand = getattr(lib, f"{pfx}kem_enc_derand")
        dec = getattr(lib, f"{pfx}kem_dec")
        pk_buf = ctypes.create_string_buffer(p.pk_bytes)
        sk_buf = ctypes.create_string_buffer(p.sk_bytes)
        ct_buf = ctypes.create_string_buffer(p.ct_bytes)
        ss_buf = ctypes.create_string_buffer(32)
        in_buf = ctypes.create_string_buffer(64)

        pk_fixed, sk_fixed = native.keygen(b"\x42" * 64, name)
        ct_fixed, _ = native.encaps(pk_fixed, b"fixed", name)
        random_sks = [native.keygen(os.urandom(64), name)[1] for _ in range(64)]
        # Random inputs are drawn before timing: an os.urandom call just before a timed call
        # perturbs caches and biases the random class (observed as |t| up to 8.8).
        seeds, msgs = [os.urandom(64) for _ in range(2 * samples)], [os.urandom(32) for _ in range(2 * samples)]

        def set_in(b):
            ctypes.memmove(in_buf, b, len(b))

        def set_sk(b):
            ctypes.memmove(sk_buf, b, len(b))

        # Key generation: fixed vs random seed.
        run(f"{name} keygen", lambda: keypair_derand(pk_buf, sk_buf, in_buf, 64),
            b"\x42" * 64, lambda i: seeds[i], set_in)
        # Encapsulation: same public key, fixed vs random message entropy.
        ctypes.memmove(pk_buf, pk_fixed, len(pk_fixed))
        run(f"{name} encaps", lambda: enc_derand(ct_buf, ss_buf, pk_buf, in_buf, 32),
            b"\x07" * 32, lambda i: msgs[i], set_in)
        # Decapsulation: same ciphertext; the fixed key accepts it, random keys reject it.
        ctypes.memmove(ct_buf, ct_fixed, len(ct_fixed))
        run(f"{name} decaps", lambda: dec(ss_buf, ct_buf, p.ct_bytes, sk_buf),
            sk_fixed, lambda i: random_sks[i % len(random_sks)], set_sk)
    print("[PASS] 6. No first-order timing dependence on secrets detected (|t| < 4.5) in any set; "
          "decapsulation takes the same time whether it accepts or rejects")


if __name__ == "__main__":
    if not all(native.available(name) for name in SETS):
        print(f"Native KEM unavailable; build {NATIVE_LIBRARY_PATH.name} with `make`.")
        sys.exit(1)
    test_1_kat()
    test_2_equivalence()
    test_3_kernels()
    test_4_malformed_keys()
    test_5_static_audit()
    test_6_timing()
    print("NATIVE KEM: ALL CHECKS PASSED")
