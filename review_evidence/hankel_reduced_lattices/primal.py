#!/usr/bin/env python3
"""
Primal uSVP at reduced dimensions: Hankel versus uniform matrices (paper, Section 4.4).

For each size n, draw LWE instances b = A s + e mod q with q = 4096 and s, e ~ CBD_2, where A is either
a Hankel matrix H_m(a) (a uniform of length n + m - 1) or a uniform m x n matrix, with the same m. Build
the Kannan embedding

    rows q e_i (i < m);  (A[:, j], e_j, 0) (j < n);  (b, 0, 1),

which contains (-e, s, -1), and run progressive BKZ 2.0 (fpylll, default strategies), two tours per block
size from beta = 3 upward, until a basis vector equals +-(-e, s, -1). The recorded success block size is
the attack-agnostic quantity compared between the two kinds of matrix: a hidden structural shortcut
that lattice reduction exploits would show up as a lower success beta for Hankel instances.

m is chosen, for each n, to minimize the block size predicted by the 2016 estimate (ADPS16 / Alkim et
al.): success once sqrt(beta) * sigma <= delta(beta)^(2 beta - d) * q^(m/d), with d = m + n + 1 and the
geometric-series assumption. Using the first m rows of H_m(a) keeps the matrix Hankel.

Usage: python primal.py <n> <trials> [workers]     (writes one line per trial, then a summary)
"""

import math
import multiprocessing as mp
import sys
import time

import numpy as np
from fpylll import BKZ, GSO, LLL, IntegerMatrix
from fpylll.algorithms.bkz2 import BKZReduction

Q = 4096
SIGMA = 1.0  # CBD_2


def cbd2(rng, size):
    bits = rng.integers(0, 2, size=(size, 4))
    return (bits[:, 0] + bits[:, 1] - bits[:, 2] - bits[:, 3]).astype(np.int64)


# Root-Hermite factor: the lattice estimator's table (measured with fpylll BKZ 2.0) for beta < 40, and
# the asymptotic formula above it (estimator/reduction.py, ReductionCost._delta, commit 53da598).
_SMALL = ((2, 1.02190), (5, 1.01862), (10, 1.01616), (15, 1.01485), (20, 1.01420), (25, 1.01342),
          (28, 1.01331), (40, 1.01295))


def delta(beta):
    if beta <= 2:
        return 1.0219
    if beta < 40:
        for i in range(1, len(_SMALL)):
            if _SMALL[i][0] > beta:
                return _SMALL[i - 1][1]
    if beta == 40:
        return _SMALL[-1][1]
    return (beta / (2 * math.pi * math.e) * (math.pi * beta) ** (1 / beta)) ** (1 / (2 * (beta - 1)))


def predicted_beta(n, m, q=Q, sigma=SIGMA):
    d = m + n + 1
    for beta in range(2, d):
        lhs = math.sqrt(beta) * sigma
        rhs = delta(beta) ** (2 * beta - d) * q ** (m / d)
        if lhs <= rhs:
            return beta
    return None


def best_m(n, m_max):
    """m <= m_max minimizing the predicted beta (ties: smallest m, which is cheapest)."""
    best = None
    for m in range(n // 4, m_max + 1):
        b = predicted_beta(n, m)
        if b is not None and (best is None or b < best[0]):
            best = (b, m)
    return best[1], best[0]


def instance(kind, n, m, seed):
    rng = np.random.default_rng(seed)
    if kind == "hankel":
        a = rng.integers(0, Q, n + m - 1)
        A = np.array([[a[i + j] for j in range(n)] for i in range(m)], dtype=np.int64)
    else:
        A = rng.integers(0, Q, (m, n)).astype(np.int64)
    s, e = cbd2(rng, n), cbd2(rng, m)
    b = (A @ s + e) % Q
    return A, b, s, e


def embedding(A, b):
    m, n = A.shape
    d = m + n + 1
    B = IntegerMatrix(d, d)
    for i in range(m):
        B[i, i] = Q
    for j in range(n):
        for i in range(m):
            B[m + j, i] = int(A[i, j])
        B[m + j, m + j] = 1
    for i in range(m):
        B[d - 1, i] = int(b[i])
    B[d - 1, d - 1] = 1
    return B


def found(B, target, rows=8):
    neg = [-x for x in target]
    for r in range(min(rows, B.nrows)):
        v = list(B[r])
        if v == target or v == neg:
            return True
    return False


def run(args):
    kind, n, m, seed = args
    A, b, s, e = instance(kind, n, m, seed)
    target = [int(-x) for x in e] + [int(x) for x in s] + [-1]
    B = embedding(A, b)
    t0 = time.time()
    LLL.reduction(B)
    if found(B, target):
        return kind, seed, 2, time.time() - t0
    M = GSO.Mat(B, float_type="d" if B.nrows < 160 else "dd")
    M.update_gso()
    bkz = BKZReduction(M)
    for beta in range(3, B.nrows + 1):
        par = BKZ.Param(block_size=beta, strategies=BKZ.DEFAULT_STRATEGY, max_loops=2,
                        flags=BKZ.MAX_LOOPS | BKZ.GH_BND)
        bkz(par)
        if found(B, target):
            return kind, seed, beta, time.time() - t0
    return kind, seed, None, time.time() - t0


def main():
    n, trials = int(sys.argv[1]), int(sys.argv[2])
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else max(1, mp.cpu_count() - 2)
    m, pred = best_m(n, int(1.2 * n))
    print(f"# n={n} m={m} (of at most {int(1.2 * n)}) q={Q} CBD_2  d={m + n + 1}  predicted beta (2016 estimate) {pred}",
          flush=True)
    jobs = [(kind, n, m, 1_000_003 * n + 2 * t + (kind == "uniform")) for t in range(trials)
            for kind in ("hankel", "uniform")]
    res = {"hankel": [], "uniform": []}
    with mp.Pool(workers) as pool:
        for kind, seed, beta, secs in pool.imap_unordered(run, jobs):
            print(f"{kind:8s} seed {seed} success_beta {beta} time {secs:.1f}s", flush=True)
            res[kind].append(beta)
    from scipy.stats import mannwhitneyu
    h = np.array([x for x in res["hankel"] if x is not None], float)
    u = np.array([x for x in res["uniform"] if x is not None], float)
    for kind, x in (("hankel", h), ("uniform", u)):
        print(f"# {kind:8s} solved {len(x)}/{trials}  mean beta {x.mean():.2f}  median {np.median(x):.1f}  "
              f"sd {x.std(ddof=1):.2f}  min {x.min():.0f}  max {x.max():.0f}", flush=True)
    p = mannwhitneyu(h, u, alternative="two-sided").pvalue
    print(f"# Mann-Whitney U, Hankel vs uniform success beta: p = {p:.3f}; mean difference {h.mean() - u.mean():+.2f}",
          flush=True)


if __name__ == "__main__":
    main()
