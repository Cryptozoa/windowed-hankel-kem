#!/usr/bin/env python3
"""
2-adic layers of Windowed Hankel LWE (WH-640: n = 640, m = 768, q = 2^12, CBD_2 secret and noise).

1. Information budget. Reducing b = H(a) s + e modulo 2^j gives b mod 2^j = H(a mod 2^j) s + e mod 2^j, so
   I(s; b mod 2^j | a) = H(b mod 2^j | a) - H(e mod 2^j) * m <= m (j - H(e mod 2^j)), since the m error
   coordinates are independent. The table compares this with the entropy of s mod 2^j (640 CBD_2 entries).
2. Roots over Z/4096 of the Arora-Ge error polynomial prod_{c in support} (t - c), for CBD_1 and CBD_2.
Run: python3 review_evidence/hankel_ring_algebraic/layers.py
"""
from fractions import Fraction
from math import log2, prod

CBD2 = {-2: Fraction(1, 16), -1: Fraction(4, 16), 0: Fraction(6, 16), 1: Fraction(4, 16), 2: Fraction(1, 16)}
N, M, Q = 640, 768, 4096


def entropy_mod(j):
    d = {}
    for v, p in CBD2.items():
        d[v % 2 ** j] = d.get(v % 2 ** j, 0) + p
    return -sum(float(p) * log2(float(p)) for p in d.values()), d


print("Information budget of the reduction modulo 2^j")
for j in range(1, 6):
    h, d = entropy_mod(j)
    dist = ", ".join(f"{k}: {v}" for k, v in sorted(d.items())) if j <= 2 else ""
    print(f"  mod {2 ** j:2d}: H(e mod 2^j) = {h:.4f} bits; I(s; b mod 2^j | a) <= {M * (j - h):7.1f} bits; "
          f"H(s mod 2^j) = {N * h:7.1f} bits  {('[' + dist + ']') if dist else ''}")
print("Roots of prod_{c=-eta}^{eta} (t - c) modulo 4096")
for eta in (1, 2):
    r = [t for t in range(Q) if prod(t - c for c in range(-eta, eta + 1)) % Q == 0]
    print(f"  eta = {eta}: {len(r)} roots (support {2 * eta + 1}): {r}")
