#!/usr/bin/env python3
"""
Decoding the Hankel code {H_m(a) s} in the Hamming metric (paper, Section 4.3, noisy Pade decoding).

Algebraic decoders (Berlekamp-Welch, Guruswami-Sudan and relatives) correct errors by their number, not
their size. For CBD_2 noise a coordinate is wrong with probability 10/16, so about 480 of the 768 public-
key coordinates are wrong. We compare this with (1) the unique-decoding radius (m - n)/2 of an MDS code of
the same length and dimension, (2) the Johnson radius m (1 - sqrt(n/m)) up to which list decoding is
possible in polynomial time for Reed-Solomon codes (Guruswami-Sudan), (3) the list-decoding capacity
radius rho*, defined by H_q(rho*) = 1 - n/m: beyond it every code of this rate over an alphabet of size
q has exponentially large lists, whatever its structure, and (4) the expected number of codewords of a
random [m, n] code over Z_q within Hamming distance w of a given word,
q^(n - m) * sum_{k <= w} C(m, k) (q - 1)^k.
"""
from math import comb, log2, sqrt

n, m, q = 640, 768, 4096
p_wrong = 10 / 16
w = round(p_wrong * m)
print(f"n = {n}, m = {m}, q = {q}; CBD_2 is nonzero with probability {p_wrong}: about {w} wrong coordinates")
print(f"unique-decoding radius of an MDS code: (m - n)/2 = {(m - n) // 2}  ({(m - n) / 2 / m:.1%})")
print(f"Johnson radius: m (1 - sqrt(n/m)) = {m * (1 - sqrt(n / m)):.1f}  ({1 - sqrt(n / m):.1%})")
def Hq(x):
    return x * log2(q - 1) / log2(q) - (x * log2(x) + (1 - x) * log2(1 - x)) / log2(q)


lo, hi = 1e-9, 1 - 1 / q
for _ in range(200):
    mid = (lo + hi) / 2
    lo, hi = (mid, hi) if Hq(mid) < 1 - n / m else (lo, mid)
print(f"list-decoding capacity radius: H_q(rho) = 1 - n/m gives rho = {lo:.4f}  ({lo * m:.1f} coordinates); "
      f"1 - n/m = {1 - n / m:.4f}")
for wt in (64, 70, 128, 256, w):
    s = sum(comb(m, k) * (q - 1) ** k for k in range(wt + 1))
    print(f"expected codewords within distance {wt:3d} of a random word: 2^{log2(s) + (n - m) * log2(q):.1f}")
