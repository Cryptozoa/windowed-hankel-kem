#!/usr/bin/env python3
"""
Check of the shift relation behind the bound in free_vectors.sage (paper, Section 4.4).

For a Hankel matrix H = H_m(a) and J = [0, n - k), take short vectors phi of the dual lattice
Lambda_J = {phi : (H^T phi)_j = 0 mod q for j in J} (BKZ-20 reduced basis). For phi with phi_{m-1} = 0, the
shift (S phi)_i = phi_{i-1} should satisfy the constraints on J - 1 = [0, n - k - 1) and, generically, not
the constraint n - k - 1; for phi_0 = 0, S^{-1} phi should satisfy them on [1, n - k + 1) and not on 0.
An attacker obtains such phi by leaving out the last (or first) sample, so the lattice is built from
rows [0, m - 1) (forward) or [1, m) (backward) of H and every reduced basis vector is tested.
"""
import os
import sys

import numpy as np
from fpylll import BKZ, IntegerMatrix, LLL

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hankel_reduced_lattices"))
import geometry as P  # noqa: E402  (inv_mod_q)

Q, n, m, k = 4096, 48, 58, 8
rng = np.random.default_rng(20261008)
stats = {"fwd": [0, 0, 0], "bwd": [0, 0, 0]}  # [checked, constraints hold, extra constraint also holds]
def reduced_dual(H, rows, cols):
    A = H[rows][:, cols]
    mm, kk = A.shape
    Ainv = P.inv_mod_q(A[:kk].T)
    if Ainv is None:
        return None
    C = (-(Ainv.dot(A[kk:].T))) % Q
    B = IntegerMatrix(mm, mm)
    for i in range(kk):
        B[i, i] = Q
    for c in range(mm - kk):
        for i in range(kk):
            B[kk + c, i] = int(C[i, c])
        B[kk + c, kk + c] = 1
    LLL.reduction(B)
    BKZ.reduction(B, BKZ.Param(block_size=20, strategies=BKZ.DEFAULT_STRATEGY, max_loops=4))
    return [np.array(list(B[r]), dtype=object) for r in range(mm)]


for trial in range(10):
    a = rng.integers(0, Q, n + m - 1)
    H = np.array([[a[i + j] for j in range(n)] for i in range(m)], dtype=object)
    J = np.arange(n - k)
    fwd = reduced_dual(H, np.arange(m - 1), J)
    bwd = reduced_dual(H, np.arange(1, m), J)
    for vecs, d in ((fwd, "fwd"), (bwd, "bwd")):
        if vecs is None:
            continue
        for v in vecs:
            phi = np.concatenate((v, [0])) if d == "fwd" else np.concatenate(([0], v))
            assert all((H[:, : n - k].T.dot(phi)) % Q == 0)
            sphi = np.concatenate(([0], phi[:-1])) if d == "fwd" else np.concatenate((phi[1:], [0]))
            w = H.T.dot(sphi) % Q
            stats[d][0] += 1
            if d == "fwd":
                stats[d][1] += all(w[: n - k - 1] == 0)
                stats[d][2] += w[n - k - 1] == 0
            else:
                stats[d][1] += all(w[1: n - k + 1] == 0)
                stats[d][2] += w[0] == 0
for d, (cnt, ok, extra) in stats.items():
    print(f"{d}: {cnt} reduced basis vectors; shifted constraints hold for {ok}/{cnt}; "
          f"the dropped constraint also holds for {extra}/{cnt}")
