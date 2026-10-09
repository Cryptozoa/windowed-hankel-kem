#!/usr/bin/env python3
"""
Does decapsulation take the same time whether it accepts or rejects? (paper, Section 8)

For each parameter set: a fixed ciphertext is decapsulated under its own secret key (accepts) or under one
of 64 other keys (rejects), in random order, 20,000 calls per class, with every input prepared before
timing. Reports the Welch t statistic (10% of the slowest calls trimmed) and the difference of medians.
The control splits the accepting calls into two random halves, which must not differ.

Run from the repository root after `make`: python3 review_evidence/hankel_decaps_timing/decaps_timing.py
"""
import ctypes
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.getcwd())
from hankel_kem import generic, native  # noqa: E402
from hankel_kem.backends import NATIVE_LIBRARY as lib  # noqa: E402

N = 20000
rng = np.random.default_rng(20261009)


def welch(a, b):
    a, b = np.sort(np.asarray(a, float)), np.sort(np.asarray(b, float))
    a, b = a[: int(len(a) * 0.9)], b[: int(len(b) * 0.9)]
    return (a.mean() - b.mean()) / np.sqrt(a.var(ddof=1) / len(a) + b.var(ddof=1) / len(b))


for name in ("WH-640", "WH-936", "WH-1208"):
    p, pfx = generic.PROFILES[name], native.PREFIX[name]
    dec = getattr(lib, f"{pfx}kem_dec")
    pk, sk = native.keygen(os.urandom(64), name)
    ct, ss = native.encaps(pk, os.urandom(32), name)
    others = [native.keygen(os.urandom(64), name)[1] for _ in range(64)]
    assert native.decaps(ct, sk, name) == ss and all(native.decaps(ct, o, name) != ss for o in others)
    ct_buf, ss_buf = ctypes.create_string_buffer(ct, len(ct)), ctypes.create_string_buffer(32)
    sk_buf = ctypes.create_string_buffer(p.sk_bytes)
    order = rng.permutation(np.repeat([0, 1], N))
    keys = [sk if c == 0 else others[i % 64] for i, c in enumerate(order)]
    t_acc, t_rej = [], []
    for c, key in zip(order, keys):
        ctypes.memmove(sk_buf, key, len(key))
        t0 = time.perf_counter_ns()
        dec(ss_buf, ct_buf, len(ct), sk_buf)
        dt = time.perf_counter_ns() - t0
        (t_acc if c == 0 else t_rej).append(dt)
    half = rng.permutation(len(t_acc))
    ctrl = welch(np.array(t_acc)[half[: len(half) // 2]], np.array(t_acc)[half[len(half) // 2:]])
    print(f"{name:8s} accept vs reject: |t| = {abs(welch(t_acc, t_rej)):.2f}, medians {np.median(t_acc) / 1e3:.2f} / "
          f"{np.median(t_rej) / 1e3:.2f} us (difference {np.median(t_acc) - np.median(t_rej):+.0f} ns); "
          f"control |t| = {abs(ctrl):.2f}", flush=True)
