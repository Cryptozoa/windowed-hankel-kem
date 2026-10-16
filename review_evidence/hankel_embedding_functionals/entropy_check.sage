# Entropy of s~ mod g for the low-degree factors of X^1407 - 1 over Z_4096 (paper, Section 4.3 and Table 10).
#
# g divides Phi_d (d = 3, 7, 21), so s~ mod g is a function of y = s~ mod Phi_d over Z, whose coefficients are
# small integers. For each d this script prints the Gaussian entropy of y (an upper bound on that of s~ mod g)
# and of the folded vector s~ mod (X^d - 1), against d coordinates of s; for each cubic and sextic factor g, the
# shortest vector of the kernel lattice of y -> s~ mod g (mod q), against the spread of y, which shows whether
# the reduction modulo g is close to injective; and, for the cubic factors, a Monte Carlo estimate of the
# collision entropy H_2 of s~ mod g (a lower bound on its Shannon entropy) from 2^22 samples.
#
# Run: sage entropy_check.sage   (conda-forge SageMath 10.9; about 10 s)
import numpy as np
from math import log2, pi, e
from fpylll import IntegerMatrix, LLL
q, n = 4096, 640
Zq = Zmod(q); R.<Y> = Zq[]
def factors_mod_q(d):
    K = Qp(2, prec=60)
    return [R([Zq(ZZ(c.lift() if hasattr(c, "lift") else c)) for c in f.monic().list()])
            for f, mult in cyclotomic_polynomial(d).change_ring(K).factor()]
def red_matrix(gpoly, ring, n):
    """column j = coefficients of X^(n-1-j) mod g (in the given ring)."""
    k = gpoly.degree(); M = matrix(ring.base_ring(), k, n); p = ring(1)
    X = ring.gen()
    for deg in range(n):
        co = p.list() + [0] * (k - len(p.list()))
        for t in range(k): M[t, n - 1 - deg] = co[t]
        p = (p * X) % gpoly
    return M
ZX.<Z> = ZZ[]
rng = np.random.default_rng(1r)
for d in (3, 7, 21):
    Phi = ZX(cyclotomic_polynomial(d))
    Rphi = red_matrix(Phi, ZX, n).change_ring(RDF)            # small integer entries over Z
    kphi = Phi.degree()
    Hphi = 0.5 * (kphi * log2(2 * pi * e) + log2(abs((Rphi * Rphi.transpose()).det())))
    folded = d * 0.5 * log2(2 * pi * e * n / d)
    print(f"d = {d}: H(s~ mod Phi_{d}) over Z ~ {Hphi:.1f} bits (degree {kphi}); "
          f"H(s~ mod X^{d}-1) ~ {folded:.1f} bits; {d} raw coordinates: {2.031 * d:.1f} bits")
    if d == 3:
        continue
    for i, g in enumerate(factors_mod_q(d)):
        k = g.degree()
        # s~ mod g = M * y (mod q), y = s~ mod Phi_d over Z, M = reduction of X^0..X^(kphi-1) mod g
        M = red_matrix(g, R, kphi)                                # k x kphi over Z_q (columns X^(kphi-1-j))
        Mz = matrix(ZZ, [[ZZ(x) for x in row] for row in M.rows()])
        # kernel lattice of y -> M y mod q, rank kphi, det q^k
        B = [[0] * kphi for _ in range(kphi)]
        A = Mz.change_ring(Zmod(q)).right_kernel_matrix()
        basis = matrix(ZZ, [[ZZ(x) for x in r] for r in A.rows()]).stack(q * identity_matrix(ZZ, kphi))
        Lb = basis.LLL()
        rows = [r for r in Lb.rows() if any(r)]
        lam1 = min(sqrt(sum(x * x for x in r)) for r in rows[:kphi])
        # spread of y = s~ mod Phi_d
        Ryy = (Rphi * Rphi.transpose())
        sig = sqrt(max(Ryy.diagonal()))
        line = (f"   factor {i} (degree {k}): kernel lattice of the mod-q map has lambda_1 ~ {float(lam1):.1f}, "
                f"against y's per-coordinate sd {float(sig):.1f}; Gaussian cap {min(Hphi, 12 * k):.1f} bits")
        if k == 3:
            # Monte Carlo collision entropy of s~ mod g: sample y via folded sums (exact CBD_2 sums are binomial)
            counts = np.bincount(np.arange(int(n)) % int(d), minlength=int(d))        # sizes of residue classes of n-1-j mod d
            Mfold = red_matrix(g, R, d)                                # k x d: X^(d-1-r) mod g
            Mf = np.array([[int(x) for x in row] for row in Mfold.rows()], dtype=np.int64)
            N = 1r << 22r
            seen = {}
            coll = 0
            for chunk in range(16r):
                f = rng.binomial(4r * counts[None, :], 0.5r, size=(N // 16r, int(d))) - 2r * counts[None, :]
                v = (f @ Mf.T) % q
                keys = (v[:, 0r] << 24r) | (v[:, 1r] << 12r) | v[:, 2r]
                u, c = np.unique(keys, return_counts=True)
                for kk, cc in zip(u.tolist(), c.tolist()):
                    seen[kk] = seen.get(kk, 0r) + cc
            tot = sum(seen.values())
            pc = float(sum(c * (c - 1r) for c in seen.values())) / float(tot * (tot - 1r))
            line += f"; Monte Carlo collision entropy H_2 ~ {-log2(pc):.1f} bits from {tot} samples"
        print(line, flush=True)
