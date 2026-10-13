#!/usr/bin/env python3
"""
Kung's realization algorithm / ERA with modal filtering, applied to Windowed Hankel LWE (paper, Section 4.3).

The Eigensystem Realization Algorithm (Kung's SVD realization, as used in modal analysis) takes the Hankel
matrix of a sequence of real (or complex) samples, truncates its SVD at the gap in the singular values,
reads off a state-space model of that order, and keeps the modes that pass confidence tests such as the
Modal Amplitude Coherence (MAC). It needs a Hankel matrix of low numerical rank. For 20 public keys of the
KEM (a expanded from random seeds as in Algorithm 1, s and e from CBD_2) we measure, with the residues
lifted to centered integers in [-q/2, q/2):

  (1) the wrap counts k = (H s + e - b) / q that the lift introduces: the integer equation is
      b = H s + e - q k, and k is unknown to the attacker;
  (2) the real singular values of H_m(a), against a uniform 768 x 640 matrix with the same entries: the
      largest ratio of consecutive singular values over the first 600 (where a truncation gap would
      appear) and over all 640, with its position, and the share of the squared norm in the top 10;
  (3) ERA on b (order 20, 384 x 383 Hankel matrix): the largest ratio of consecutive singular values
      (the gap that sets the model order) and the number of modes with MAC > 0.9, against a uniform
      sequence of the same length;
  (4) contrasts: a sequence from an order-64 linear recurrence mod q (Hankel rank at most 64 over Z_q,
      found at once by Berlekamp-Massey) and five damped real modes with 10% noise (what ERA is made for).

MAC follows Juang and Pappa: for each identified mode j with pole lambda_j, the correlation between the
modal amplitude history extracted from the data and the ideal history c * lambda_j^t. MPC measures the
collinearity of a mode shape across several sensors and has no meaning for a single sequence.
Run from the repository root: python3 review_evidence/hankel_era_realization/era.py
"""
import os
import sys

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view
from scipy.stats import mannwhitneyu

sys.path.insert(0, os.getcwd())
from hankel_kem import generic as g  # noqa: E402

p = g.WH640
n, m, L, q = p.n, p.m, p.L, p.q
KEYS, ORDER, ROWS = 20, 20, 384
rng = np.random.default_rng(20261013)
cen = lambda x: ((np.asarray(x, dtype=np.int64) + q // 2) % q) - q // 2


def hankel(y, rows, cols, off=0):
    return sliding_window_view(np.asarray(y, dtype=float)[off:off + rows + cols - 1], cols)[:rows]


def gap(S, hi=None):
    """Largest ratio of consecutive singular values among S[1:hi], the top one excluded."""
    s = S[1:hi]
    return float(np.max(s[:-1] / s[1:]))


def gap_at(S, hi=None):
    """1-based index i of the largest ratio S_i / S_(i+1) among S[1:hi], the top one excluded."""
    s = S[1:hi]
    return int(np.argmax(s[:-1] / s[1:])) + 2


def energy(S, r=10):
    """Fraction of the squared Frobenius norm in the r largest singular values."""
    return float((S[:r] ** 2).sum() / (S ** 2).sum())


def era(y, order=ORDER, rows=ROWS):
    """Kung / ERA on a scalar sequence; returns the singular values and the MAC of each identified mode."""
    cols = len(y) - rows
    H0, H1 = hankel(y, rows, cols), hankel(y, rows, cols, 1)
    U, S, Vt = np.linalg.svd(H0, full_matrices=False)
    Ur, Sr, Vr = U[:, :order], S[:order], Vt[:order]
    Sh = np.diag(Sr ** -0.5)
    A = Sh @ Ur.T @ H1 @ Vr.T @ Sh
    lam, Psi = np.linalg.eig(A)
    Q = np.linalg.solve(Psi, np.diag(Sr ** 0.5) @ Vr)  # modal amplitude histories from the data
    mac = []
    for j in range(order):
        ideal = Q[j, 0] * lam[j] ** np.arange(cols)
        mac.append(abs(np.vdot(ideal, Q[j])) / (np.linalg.norm(ideal) * np.linalg.norm(Q[j])))
    return S, np.array(mac)


def entropy_bits(x):
    _, counts = np.unique(x, return_counts=True)
    pr = counts / counts.sum()
    return float(-(pr * np.log2(pr)).sum())


def rank_mod2(M):
    M = (np.array(M, dtype=np.uint8) & 1).copy()
    r = 0
    for c in range(M.shape[1]):
        piv = next((i for i in range(r, M.shape[0]) if M[i, c]), None)
        if piv is None:
            continue
        M[[r, piv]] = M[[piv, r]]
        nz = np.nonzero(M[:, c])[0]
        M[nz[nz != r]] ^= M[r]
        r += 1
    return r


print(f"n = {n}, m = {m}, L = {L}, q = {q}; {KEYS} keys; ERA order {ORDER}, Hankel {ROWS} x {m - ROWS}")
rows = []
for t in range(KEYS):
    a = g.expand_a(p, rng.bytes(32))
    s = g.cbd2(rng.bytes(n))
    e = g.cbd2(rng.bytes(m))
    H = hankel(a, m, n).astype(np.int64)
    b = (H @ s + e) % q
    Hc = hankel(cen(a), m, n).astype(np.int64)
    k = (Hc @ s + e - cen(b)) // q
    assert np.all(Hc @ s + e - q * k == cen(b))
    S_H = np.linalg.svd(Hc.astype(float), compute_uv=False)
    S_U = np.linalg.svd(cen(rng.integers(0, q, (m, n))).astype(float), compute_uv=False)
    S_b, mac_b = era(cen(b))
    S_u, mac_u = era(cen(rng.integers(0, q, m)))
    rows.append(dict(k_std=k.std(), k_min=k.min(), k_max=k.max(), k_h=entropy_bits(k),
                     rank=int(np.sum(S_H > S_H[0] * 1e-10)), gH=gap(S_H, 600), gU=gap(S_U, 600),
                     aH=gap(S_H), aU=gap(S_U), pH=gap_at(S_H), pU=gap_at(S_U),
                     bH=gap_at(S_H, 600), bU=gap_at(S_U, 600), eH=energy(S_H), eU=energy(S_U),
                     cH=S_H[-1] / S_H[1], cU=S_U[-1] / S_U[1],
                     gb=gap(S_b[:ORDER + 20]), gu=gap(S_u[:ORDER + 20]),
                     mb=int((mac_b > 0.9).sum()), mu=int((mac_u > 0.9).sum()),
                     medb=float(np.median(mac_b)), medu=float(np.median(mac_u))))
    r = rows[-1]
    print(f"key {t:2d}: wraps std {r['k_std']:.2f} in [{r['k_min']}, {r['k_max']}], {r['k_h']:.2f} bits | "
          f"H_m(a) real rank {r['rank']}, gap {r['gH']:.3f} at {r['bH']} (uniform {r['gU']:.3f} at {r['bU']}), "
          f"all {r['aH']:.3f} at {r['pH']} (uniform {r['aU']:.3f} at {r['pU']}) | "
          f"ERA gap b {r['gb']:.3f} (uniform {r['gu']:.3f}), MAC>0.9 b {r['mb']:2d} (uniform {r['mu']:2d})")

col = lambda key: np.array([r[key] for r in rows], dtype=float)
rng_ = lambda key: f"{col(key).min():.3f}-{col(key).max():.3f}"
mw = lambda k1, k2: mannwhitneyu(col(k1), col(k2), alternative="two-sided").pvalue
kh = col("k_h")
print("\nSummary over the keys (ranges; Mann-Whitney p for KEM against uniform):")
print(f"  wrap counts: std {rng_('k_std')}, extremes {int(col('k_min').min())} to {int(col('k_max').max())}, "
      f"entropy {kh.min():.2f}-{kh.max():.2f} bits per equation, {m * kh.min():.0f}-{m * kh.max():.0f} bits "
      f"over {m} equations (secret: 1,300 bits)")
print(f"  H_m(a), real: rank {int(col('rank').min())}-{int(col('rank').max())} of {n}; largest consecutive ratio "
      f"over singular values 2-600 {rng_('gH')} at positions {int(col('bH').min())}-{int(col('bH').max())} "
      f"(uniform matrix {rng_('gU')}, p = {mw('gH', 'gU'):.3f}); share of the squared norm in the top 10 singular "
      f"values {rng_('eH')} (uniform {rng_('eU')}); over all "
      f"{rng_('aH')} (uniform {rng_('aU')}, p = {mw('aH', 'aU'):.3f}), at positions {int(col('pH').min())}-"
      f"{int(col('pH').max())} (uniform {int(col('pU').min())}-{int(col('pU').max())}); smallest / second "
      f"singular value {rng_('cH')} (uniform {rng_('cU')})")
print(f"  ERA on b: largest consecutive ratio {rng_('gb')} (uniform sequence {rng_('gu')}, p = {mw('gb', 'gu'):.3f}); "
      f"modes with MAC > 0.9 of {ORDER}: {int(col('mb').min())}-{int(col('mb').max())}, mean {col('mb').mean():.1f} "
      f"(uniform {int(col('mu').min())}-{int(col('mu').max())}, mean {col('mu').mean():.1f}, p = {mw('mb', 'mu'):.3f}); "
      f"median MAC p = {mw('medb', 'medu'):.3f}")

# contrast 1: an order-64 linear recurrence mod q
c = rng.integers(0, q, 64)
r_ = [int(x) for x in rng.integers(0, q, 64)]
while len(r_) < L:
    r_.append(int(np.dot(c, r_[-64:][::-1]) % q))
H_r = hankel(r_, m, n).astype(np.int64)
S_r = np.linalg.svd(hankel(cen(r_), m, n), compute_uv=False)
S_re, mac_re = era(cen(r_[:m]))
print(f"\nContrast, order-64 recurrence mod q: rank of H_m(a) mod 2 {rank_mod2(H_r)}; real rank "
      f"{int(np.sum(S_r > S_r[0] * 1e-10))} of {n}, largest consecutive ratio {gap(S_r):.3f}; "
      f"ERA gap {gap(S_re[:ORDER + 20]):.3f}, MAC > 0.9: {int((mac_re > 0.9).sum())} of {ORDER}")

# contrast 2: five damped real modes (ten poles) with 10% noise
tt = np.arange(m)
y = sum(np.exp(-0.002 * (i + 1) * tt) * np.cos(0.3 * (i + 1) * tt + i) for i in range(5))
y = y + 0.1 * y.std() * rng.standard_normal(m)
S_y, mac_y = era(y, order=10)
print(f"Contrast, five damped modes + 10% noise: ERA gap {gap(S_y[:30]):.3f} after singular value "
      f"{int(np.argmax(S_y[1:29] / S_y[2:30])) + 2}, MAC > 0.9: {int((mac_y > 0.9).sum())} of 10")
