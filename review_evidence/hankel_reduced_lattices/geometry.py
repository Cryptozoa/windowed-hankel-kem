#!/usr/bin/env python3
"""
Lattice geometry at reduced dimensions: Hankel versus uniform matrices, without a planted target
(paper, Section 4.4).

For A in Z_q^{m x n} (Hankel H_m(a) or uniform; q = 4096), reduce with BKZ 2.0 at a fixed block size:

  primal  Lambda(A)      = {(x, y) : x = A y mod q},  dimension m + n, determinant q^m
          basis rows q e_i (i < m) and (A[:, j], e_j) (j < n);
  dualsec Lambda(A^T)    = {(w, phi) : w = A^T phi mod q},  dimension n + m, determinant q^n: the lattice
          of the dual attack, whose short vectors give phi^T b = w^T s + phi^T e mod q;
          basis rows q e_j (j < n) and (A[i, :], e_i) (i < m);
  dual    Lambda_perp(A) = {phi : A^T phi = 0 mod q},  dimension m, determinant q^n,
          basis from A = [A1; A2] with A1 invertible mod q: rows q e_i (i < n) and
          (-(A1^{-T} A2^T)[:, k], e_k) (k < m - n), after a row permutation if A1 is singular mod 2.

and record log2 of the first basis vector's norm relative to the Gaussian heuristic, the achieved root
Hermite factor, and the slope of the log Gram-Schmidt profile over the middle half of the basis. A
structural shortcut available to lattice reduction would show as shorter first vectors or a different
profile for Hankel lattices.

In the q-ary regime the first reduced vector can be a trivial vector of length q, which makes that
metric uninformative; the Gram-Schmidt slope remains meaningful.

Usage: python geometry.py <primal|dualsec|dual> <n> <m> <beta> <trials> [workers]
"""

import math
import multiprocessing as mp
import sys

import numpy as np
from fpylll import BKZ, GSO, LLL, IntegerMatrix
from fpylll.algorithms.bkz2 import BKZReduction

Q = 4096


def matrix_A(kind, n, m, rng):
    if kind == "hankel":
        a = rng.integers(0, Q, n + m - 1)
        return np.array([[a[i + j] for j in range(n)] for i in range(m)], dtype=np.int64)
    return rng.integers(0, Q, (m, n)).astype(np.int64)


def inv_mod_q(M):
    """Inverse of a square integer matrix modulo Q = 2^12 (None if singular mod 2)."""
    k = M.shape[0]
    A = [[int(x) % Q for x in row] + [int(i == j) for j in range(k)] for i, row in enumerate(M)]
    for c in range(k):
        p = next((r for r in range(c, k) if A[r][c] % 2 == 1), None)
        if p is None:
            return None
        A[c], A[p] = A[p], A[c]
        inv = pow(A[c][c], -1, Q)
        A[c] = [(x * inv) % Q for x in A[c]]
        for r in range(k):
            if r != c and A[r][c]:
                f = A[r][c]
                A[r] = [(x - f * y) % Q for x, y in zip(A[r], A[c])]
    return np.array([row[k:] for row in A], dtype=object)


def basis(kind, mode, n, m, seed):
    rng = np.random.default_rng(seed)
    A = matrix_A(kind, n, m, rng)
    if mode == "dualsec":
        d = m + n
        B = IntegerMatrix(d, d)
        for j in range(n):
            B[j, j] = Q
        for i in range(m):
            for j in range(n):
                B[n + i, j] = int(A[i, j])
            B[n + i, n + i] = 1
        return B, d, n * math.log2(Q)
    if mode == "primal":
        d = m + n
        B = IntegerMatrix(d, d)
        for i in range(m):
            B[i, i] = Q
        for j in range(n):
            for i in range(m):
                B[m + j, i] = int(A[i, j])
            B[m + j, m + j] = 1
        return B, d, m * math.log2(Q)
    # dual: find n rows of A invertible mod q (try the first n, then random subsets)
    order = np.arange(m)
    for attempt in range(50):
        Ainv = inv_mod_q(A[order[:n]].T)  # (A1^T)^{-1}
        if Ainv is not None:
            break
        order = rng.permutation(m)
    else:
        raise RuntimeError("no invertible n x n submatrix found")
    A1T_inv, A2T = Ainv, A[order[n:]].T.astype(object)
    C = (-(A1T_inv.dot(A2T))) % Q  # n x (m - n): phi1 = C phi2
    B = IntegerMatrix(m, m)
    for i in range(n):
        B[i, i] = Q
    for k in range(m - n):
        for i in range(n):
            B[n + k, i] = int(C[i, k])
        B[n + k, n + k] = 1
    return B, m, n * math.log2(Q)


def log2_gh(d, logdet2):
    return (math.lgamma(d / 2 + 1) / math.log(2)) / d + logdet2 / d - 0.5 * math.log2(math.pi)


def run(args):
    kind, mode, n, m, beta, seed = args
    B, d, logdet2 = basis(kind, mode, n, m, seed)
    LLL.reduction(B)
    M = GSO.Mat(B, float_type="d" if d < 160 else "dd")
    M.update_gso()
    BKZReduction(M)(BKZ.Param(block_size=beta, strategies=BKZ.DEFAULT_STRATEGY, max_loops=8,
                              flags=BKZ.MAX_LOOPS | BKZ.AUTO_ABORT))
    M.update_gso()
    r = [math.log2(M.get_r(i, i)) / 2 for i in range(d)]  # log2 ||b_i*||
    b1 = math.log2(B[0].norm())
    rhf = 2 ** ((b1 - logdet2 / d) / d)
    lo, hi = d // 4, 3 * d // 4
    slope = np.polyfit(np.arange(lo, hi), r[lo:hi], 1)[0]
    return kind, seed, b1 - log2_gh(d, logdet2), rhf, slope


def main():
    mode, n, m, beta, trials = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
    workers = int(sys.argv[6]) if len(sys.argv) > 6 else max(1, mp.cpu_count() - 2)
    print(f"# {mode} lattice: n={n} m={m} q={Q} BKZ-{beta} (8 tours max), {trials} trials per kind", flush=True)
    jobs = [(kind, mode, n, m, beta, 7_000_001 * n + 2 * t + (kind == "uniform")) for t in range(trials)
            for kind in ("hankel", "uniform")]
    res = {"hankel": [], "uniform": []}
    with mp.Pool(workers) as pool:
        for kind, seed, rel, rhf, slope in pool.imap_unordered(run, jobs):
            print(f"{kind:8s} seed {seed} log2(|b1|/GH) {rel:+.4f} rhf {rhf:.5f} gs_slope {slope:.5f}", flush=True)
            res[kind].append((rel, rhf, slope))
    from scipy.stats import mannwhitneyu
    for idx, name in ((0, "log2(|b1|/GH)"), (1, "root Hermite factor"), (2, "GS slope")):
        h = np.array([x[idx] for x in res["hankel"]])
        u = np.array([x[idx] for x in res["uniform"]])
        p = mannwhitneyu(h, u, alternative="two-sided").pvalue
        print(f"# {name:20s} Hankel {h.mean():+.5f} (sd {h.std(ddof=1):.5f})  uniform {u.mean():+.5f} "
              f"(sd {u.std(ddof=1):.5f})  Mann-Whitney p = {p:.3f}", flush=True)


if __name__ == "__main__":
    main()
