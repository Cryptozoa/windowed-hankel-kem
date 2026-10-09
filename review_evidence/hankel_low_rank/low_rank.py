#!/usr/bin/env python3
"""
Low-rank Hankel methods and the degrees of freedom of public matrices (paper, Sections 4.2 and 4.3).

Prony-type methods, Berlekamp-Massey and the spectral learning of weighted automata exploit a Hankel matrix
of low rank, that is, a sequence with a short linear recurrence. For five public keys of the KEM
(a expanded from random seeds as in Algorithm 1, s and e from CBD_2) we report the rank of H_m(a) modulo 2
and the linear complexity over GF(2) of a mod 2 and b mod 2 (Berlekamp-Massey); a random sequence of
length N has linear complexity about N/2. As a contrast, a sequence a produced by a 64-cell linear-feedback
shift register (here of linear complexity 63) gives H_m(a) of rank at most its linear complexity.

It also computes the secret entropies used in the comparison of Section 4.2: CBD_2 and CBD_3 exactly, and
the discrete Gaussian of standard deviation 2.8 (FrodoKEM-640) numerically.
Run from the repository root: python3 review_evidence/hankel_low_rank/low_rank.py
"""
import math
import os
import sys

import numpy as np

sys.path.insert(0, os.getcwd())
from hankel_kem import generic as g  # noqa: E402

p = g.WH640
n, m, L = p.n, p.m, p.L


def rank_mod2(M):
    M = (np.array(M, dtype=np.uint8) & 1).copy()
    r = 0
    rows, cols = M.shape
    for c in range(cols):
        piv = next((i for i in range(r, rows) if M[i, c]), None)
        if piv is None:
            continue
        M[[r, piv]] = M[[piv, r]]
        nz = np.nonzero(M[:, c])[0]
        nz = nz[nz != r]
        M[nz] ^= M[r]
        r += 1
        if r == rows:
            break
    return r


def linear_complexity_gf2(bits):
    """Berlekamp-Massey over GF(2)."""
    s = [int(x) & 1 for x in bits]
    N = len(s)
    c, b = [1] + [0] * N, [1] + [0] * N
    L_, mm = 0, -1
    for i in range(N):
        d = s[i]
        for j in range(1, L_ + 1):
            d ^= c[j] & s[i - j]
        if d:
            t = c[:]
            shift = i - mm
            for j in range(N + 1 - shift):
                c[j + shift] ^= b[j]
            if 2 * L_ <= i:
                L_, mm, b = i + 1 - L_, i, t
    return L_


rng = np.random.default_rng(20261009)
print(f"n = {n}, m = {m}, L = {L}")
for t in range(5):
    seed = rng.bytes(32)
    a = g.expand_a(p, seed)
    H = np.array([[a[i + j] for j in range(n)] for i in range(m)])
    s = g.cbd2(rng.bytes(n))
    e = g.cbd2(rng.bytes(m))
    b = (H @ s + e) % p.q
    print(f"key {t}: rank of H_m(a) mod 2 = {rank_mod2(H)}; linear complexity over GF(2): "
          f"a mod 2 {linear_complexity_gf2(a)} of {L}, b mod 2 {linear_complexity_gf2(b)} of {m}")

# contrast: a from a 64-cell LFSR; any linear recurrence of order d bounds the rank of H_m(a) by d
taps = [64, 63, 61, 60]
state = [int(x) for x in rng.integers(0, 2, 64)]
seq = []
for _ in range(L):
    seq.append(state[-1])
    fb = 0
    for tp in taps:
        fb ^= state[64 - tp]
    state = [fb] + state[:-1]
H_lfsr = np.array([[seq[i + j] for j in range(n)] for i in range(m)])
print(f"LFSR contrast: linear complexity of a {linear_complexity_gf2(seq)}, rank of H_m(a) mod 2 = {rank_mod2(H_lfsr)}")


def entropy(probs):
    return -sum(x * math.log2(x) for x in probs if x > 0)


cbd = lambda eta: [math.comb(2 * eta, k) / 4 ** eta for k in range(2 * eta + 1)]
h2, h3 = entropy(cbd(2)), entropy(cbd(3))
w = [math.exp(-x * x / (2 * 2.8 ** 2)) for x in range(-40, 41)]
hg = entropy([x / sum(w) for x in w])
print(f"entropy per coefficient: CBD_2 {h2:.3f}, CBD_3 {h3:.3f}, discrete Gaussian sigma 2.8 {hg:.3f} bits")
print(f"secret entropy: Windowed Hankel 640 x CBD_2 = {640 * h2:.0f} bits; ML-KEM-512 512 x CBD_3 = {512 * h3:.0f} bits; "
      f"FrodoKEM-640, one column of S, 640 x Gaussian(2.8) = {640 * hg:.0f} bits")
print("values defining the public matrix: Windowed Hankel 1,407 (768 x 640); ML-KEM-512 2 x 2 x 256 = 1,024 "
      "(512 x 512); FrodoKEM-640 640 x 640 = 409,600")
