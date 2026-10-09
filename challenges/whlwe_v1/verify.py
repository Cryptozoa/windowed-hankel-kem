#!/usr/bin/env python3
"""
Verify a solution to a Windowed Hankel LWE challenge instance.

  python3 verify.py whlwe-v1-n0128-hankel solution.txt
  python3 verify.py whlwe-v1-n0128-hankel -          (secret read from standard input)
  python3 verify.py --matrix whlwe-v1-n0128-hankel   (print A and b, one row per line: A[i][0..n-1] b[i])

A solution is the secret s, given as n integers separated by commas, spaces or newlines. It is correct if
its commitment matches the published one. The residual b - A s mod q is also reported: a vector s other
than the committed one with a residual in the CBD_2 range [-2, 2] would itself be worth reporting.
"""

import re
import sys

import whlwe_challenge as wc


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--matrix":
        inst = wc.load(sys.argv[2])
        A = wc.public_matrix(inst["n"], inst["m"], inst["kind"], bytes.fromhex(inst["public_seed"]))
        for row, bi in zip(A, inst["b"]):
            print(" ".join(str(int(x)) for x in row), bi)
        return
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    inst = wc.load(sys.argv[1])
    text = sys.stdin.read() if sys.argv[2] == "-" else open(sys.argv[2]).read()
    try:
        s = [int(t) for t in re.split(r"[\s,\[\]]+", text) if t]
    except ValueError as exc:
        sys.exit(f"the solution must be a list of integers ({exc})")
    res = wc.check(inst, s)
    for k, v in res.items():
        print(f"{k}: {v}")
    print("SOLVED" if res["ok"] else "not solved")
    sys.exit(0 if res["ok"] else 1)


if __name__ == "__main__":
    main()
