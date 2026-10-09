#!/usr/bin/env python3
"""
Baseline solver: the generic primal attack, for comparison with structural attacks.

  python3 baseline.py whlwe-v1-n0128-hankel [--max-beta 60] [--samples M] [--out solution.txt]

Builds the Kannan embedding of b = A s + e from the public data only (rows q e_i, (A[:, j], e_j) and
(b, 0, 1), which contain (-e, s, -1)), runs progressive BKZ 2.0 with two tours per block size, and stops
when a basis vector yields a secret whose commitment matches. Uses the first M samples (default: all);
for Hankel instances the first M rows of H_m(a) form H_M(a). Requires fpylll.

This is the attack that a structural attack should beat: solving a Hankel instance at a clearly smaller
block size than its uniform twin, over several sizes, would be evidence of a weakness.
"""

import argparse
import sys
import time

import numpy as np
from fpylll import BKZ, GSO, LLL, IntegerMatrix
from fpylll.algorithms.bkz2 import BKZReduction

import whlwe_challenge as wc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("instance")
    ap.add_argument("--max-beta", type=int, default=60)
    ap.add_argument("--samples", type=int, default=None)
    ap.add_argument("--out", default=None, help="write the secret here (default: report the block size only)")
    args = ap.parse_args()

    inst = wc.load(args.instance)
    n, m, q = inst["n"], args.samples or inst["m"], wc.Q
    A = wc.public_matrix(n, inst["m"], inst["kind"], bytes.fromhex(inst["public_seed"]))[:m]
    b = np.array(inst["b"][:m], dtype=np.int64)
    d = m + n + 1
    B = IntegerMatrix(d, d)
    for i in range(m):
        B[i, i] = q
    for j in range(n):
        for i in range(m):
            B[m + j, i] = int(A[i, j])
        B[m + j, m + j] = 1
    for i in range(m):
        B[d - 1, i] = int(b[i])
    B[d - 1, d - 1] = 1

    t0 = time.time()
    LLL.reduction(B)
    M = GSO.Mat(B, float_type="d" if d < 160 else "dd")
    M.update_gso()
    bkz = BKZReduction(M)
    for beta in range(2, args.max_beta + 1):
        if beta > 2:
            bkz(BKZ.Param(block_size=beta, strategies=BKZ.DEFAULT_STRATEGY, max_loops=2, flags=BKZ.MAX_LOOPS))
        for r in range(min(10, d)):
            v = list(B[r])
            if abs(v[-1]) == 1:
                s = [-x * v[-1] for x in v[m:m + n]]  # v = +-(-e, s, -1)
                if wc.check(inst, s)["ok"]:
                    print(f"{inst['name']}: SOLVED at block size {beta} ({m} samples, dimension {d}, "
                          f"{time.time() - t0:.1f} s)")
                    if args.out:
                        with open(args.out, "w") as f:
                            f.write(",".join(map(str, s)) + "\n")
                    return 0
    print(f"{inst['name']}: not solved up to block size {args.max_beta} ({time.time() - t0:.1f} s)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
