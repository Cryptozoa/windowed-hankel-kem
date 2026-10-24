#!/usr/bin/env python3
"""
Algebraic systems over Z/2^k for Windowed Hankel LWE at toy size: Hankel versus uniform matrices.

Arora-Ge-style attacks encode bounded noise as polynomial equations. With CBD_1 secret and noise, each
sample gives l_i^3 - l_i = 0 with l_i = b_i - <A_i, x>, and each coordinate x_j^3 - x_j = 0, now over the
scheme's own ring Z/Q, Q = 2^k, rather than over the field GF(4093) of Appendix E. Over Z/2^k the cubic
t^3 - t has five roots, {0, 1, -1, 2^(k-1) - 1, 2^(k-1) + 1}, so the system can have spurious solutions,
and Groebner bases over the ring need not isolate a unique solution (polynomials such as 8x(x-1) vanish
on every root mod 16 without lying in the ideal). We therefore count solutions exactly: every candidate
x in R^n, R the five roots, is tested against all m equations. Any algebraic solver must at least
resolve this solution set, so a Hankel-specific degeneracy would show as different counts.

For each (Q, n, m), 64 Hankel instances (a_0..a_{m+n-2} uniform, A_ij = a_{i+j}) and 64 uniform ones,
CBD_1 secret and noise. Reported: mean number of solutions and the fraction with a unique solution, with
a 95% Wilson-style normal interval for the difference of unique fractions (Hankel - uniform) and the
smallest margin d for which a two one-sided test at level 0.05 would declare |difference| < d.

Run: python3 review_evidence/hankel_ring_algebraic/solution_counts.py  (about a minute)
"""
import itertools
import math
import random
import statistics

import numpy as np

TRIALS = 64


def roots(Q):
    return [t for t in range(Q) if (t ** 3 - t) % Q == 0]


def instance(n, m, Q, kind, rng):
    if kind == "hankel":
        a = [rng.randrange(Q) for _ in range(m + n - 1)]
        A = np.array([[a[i + j] for j in range(n)] for i in range(m)], dtype=np.int64)
    else:
        A = np.array([[rng.randrange(Q) for _ in range(n)] for _ in range(m)], dtype=np.int64)
    s = np.array([rng.choice((-1, 0, 0, 1)) for _ in range(n)], dtype=np.int64)
    e = np.array([rng.choice((-1, 0, 0, 1)) for _ in range(m)], dtype=np.int64)
    return A, (A @ s + e) % Q


def count_solutions(A, b, X, Q):
    total = 0
    for lo in range(0, len(X), 200000):
        L = (b[None, :] - X[lo:lo + 200000] @ A.T) % Q
        total += int((((L * L % Q) * L - L) % Q == 0).all(axis=1).sum())
    return total


def tost_margin(p1, p2, n1, n2):
    d = p1 - p2
    se = math.sqrt(max(p1 * (1 - p1), 1e-12) / n1 + max(p2 * (1 - p2), 1e-12) / n2)
    return d, (d - 1.96 * se, d + 1.96 * se), abs(d) + 1.645 * se


def main():
    print(f"{TRIALS} instances per kind; CBD_1 secret and noise; candidates = roots of x^3 = x in each coordinate")
    for Q in (16, 4096):
        R = roots(Q)
        print(f"Q = {Q}: roots of t^3 - t: {R}")
        for n, ms in ((4, (8, 12, 16, 24)), (6, (12, 16, 20, 28)), (8, (16, 20, 24, 32))):
            X = np.array(list(itertools.product(R, repeat=n)), dtype=np.int64)
            for m in ms:
                stats = {}
                for kind in ("hankel", "uniform"):
                    counts = []
                    for t in range(TRIALS):
                        rng = random.Random(f"{Q}-{n}-{m}-{kind}-{t}")
                        A, b = instance(n, m, Q, kind, rng)
                        counts.append(count_solutions(A, b, X, Q))
                    stats[kind] = (statistics.mean(counts), sum(c == 1 for c in counts) / TRIALS)
                (mh, uh), (mu, uu) = stats["hankel"], stats["uniform"]
                d, ci, margin = tost_margin(uh, uu, TRIALS, TRIALS)
                print(f"  n={n} m={m:2d}: mean solutions hankel {mh:6.2f} uniform {mu:6.2f} | unique "
                      f"{uh:.3f} vs {uu:.3f}, diff {d:+.3f}, 95% CI [{ci[0]:+.3f}, {ci[1]:+.3f}], "
                      f"TOST margin {margin:.3f}", flush=True)


if __name__ == "__main__":
    main()
