import ctypes, os, sys, time
import numpy as np
sys.path.insert(0, os.getcwd())
from hankel_kem import generic, native
from hankel_kem.backends import NATIVE_LIBRARY as lib
from test_hankel_native_kem import _welch
rng = np.random.default_rng()
def run(call, fixed, rand, setup, samples=4000):
    order = rng.integers(0, 2, 2 * samples); tf, tr = [], []
    for i, c in enumerate(order):
        setup(fixed if c == 0 else rand(i)); t0 = time.perf_counter_ns(); call()
        (tf if c == 0 else tr).append(time.perf_counter_ns() - t0)
    return _welch(tf, tr)
for name, op in (("WH-1208", "encaps"), ("WH-936", "encaps")):
    p, pfx = generic.PROFILES[name], native.PREFIX[name]
    pk = ctypes.create_string_buffer(p.pk_bytes); sk = ctypes.create_string_buffer(p.sk_bytes)
    ct = ctypes.create_string_buffer(p.ct_bytes); ss = ctypes.create_string_buffer(32); ib = ctypes.create_string_buffer(64)
    set_in = lambda b: ctypes.memmove(ib, b, len(b))
    if op == "keygen":
        f = getattr(lib, pfx + "kem_keypair_derand"); call = lambda: f(pk, sk, ib, 64); pre = [os.urandom(64) for _ in range(8000)]; fx, rd = b"\x42" * 64, lambda i: pre[i]
    else:
        f = getattr(lib, pfx + "kem_enc_derand"); pkf, _ = native.keygen(b"\x42" * 64, name); ctypes.memmove(pk, pkf, len(pkf))
        call = lambda: f(ct, ss, pk, ib, 32); pre = [os.urandom(32) for _ in range(8000)]; fx, rd = b"\x07" * 32, lambda i: pre[i]
    ts = [run(call, fx, rd, set_in) for _ in range(12)]
    print(name, op, " ".join(f"{t:+.2f}" for t in ts))
