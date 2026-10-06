"""Per-operation latency of the Windowed Hankel KEM (e2 version) with the NEON backend."""
import os, sys, time, statistics, platform, json
sys.path.insert(0, os.getcwd())
import numpy as np
import hankel_kem_core as core
import hankel_kem_wrapper as kem

BACKEND = sys.argv[1] if len(sys.argv) > 1 else "neon"
N_RUNS, WARM = 2000, 200
pool = [(os.urandom(64), os.urandom(32)) for _ in range(WARM + N_RUNS)]
keys = [kem.hankel_kem_keygen(s, backend=BACKEND) for s, _ in pool]
cts = [kem.hankel_kem_encaps(pk, e, backend=BACKEND) for (pk, _), (_, e) in zip(keys, pool)]
for (pk, sk), (ct, ss) in zip(keys, cts):  # correctness outside timing
    assert kem.hankel_kem_decaps(ct, sk, backend=BACKEND) == ss

def bench(fn, args):
    for a in args[:WARM]: fn(*a)
    t = []
    for a in args[WARM:]:
        s = time.perf_counter_ns(); fn(*a); t.append(time.perf_counter_ns() - s)
    return statistics.median(t) / 1e3, np.percentile(t, 90) / 1e3

kg = bench(lambda s: kem.hankel_kem_keygen(s, backend=BACKEND), [(s,) for s, _ in pool])
en = bench(lambda pk, e: kem.hankel_kem_encaps(pk, e, backend=BACKEND), [(pk, e) for (pk, _), (_, e) in zip(keys, pool)])
de = bench(lambda ct, sk: kem.hankel_kem_decaps(ct, sk, backend=BACKEND), [(ct, sk) for (pk, sk), (ct, _) in zip(keys, cts)])
def hs(s, e):
    pk, sk = kem.hankel_kem_keygen(s, backend=BACKEND)
    ct, a = kem.hankel_kem_encaps(pk, e, backend=BACKEND)
    return kem.hankel_kem_decaps(ct, sk, backend=BACKEND)
h = bench(hs, pool)
print(f"backend={BACKEND} runs={N_RUNS} python={platform.python_version()} numpy={np.__version__} {platform.machine()}")
for name, (med, p90) in [("keygen", kg), ("encaps", en), ("decaps", de), ("handshake", h)]:
    print(f"{name:10s} median {med:8.1f} us   p90 {p90:8.1f} us")
