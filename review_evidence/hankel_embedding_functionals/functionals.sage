# Short functionals from the cyclic embedding of Windowed Hankel LWE (paper, Appendix C).
#
# A public key b = H_m(a) s + e is the window of degrees n-1 .. L-1 of a(X) s~(X) mod (X^L - 1),
# L = n + m - 1, where s~ is the reversal of s. For a factor g of X^L - 1 over Z/qZ of degree k,
# a functional phi in Z^m with  H_m(a)^T phi = R_g^T c (mod q)  for some c gives
#     phi^T b = c^T (s~ mod g) + phi^T e,
# so it depends on s only through the k coefficients of s~ mod g. Such functionals form the q-ary
# lattice  Lambda_g = { phi : B_g phi = 0 mod q },  with B_g in Z_q^{(n-k) x m} obtained by
# eliminating c (k = 0, g = 1 is the plain dual lattice). This script
#   (1) factors X^1407 - 1 over Z/2^12 and lists its low-degree factors;
#   (2) at full size (n = 640, m = 768), checks for random a that B_g has full rank mod 2, i.e. that
#       Lambda_g has determinant q^(n-k) exactly as for a uniform matrix, and reports the Gaussian
#       heuristic for its shortest vector and the advantage of a functional of that length;
#   (3) at reduced sizes, computes exact shortest vectors of Lambda_g for Hankel and for uniform
#       matrices of the same shape and compares them with the Gaussian heuristic.
#
# Run with a SageMath that has fpylll (tested: conda-forge SageMath 10.9):
#   sage functionals.sage [full|small|all]

import sys, time
from math import lgamma, log2, exp, pi, sqrt, e as E
from fpylll import IntegerMatrix, LLL, BKZ, SVP
from fpylll.algorithms.bkz2 import BKZReduction

q = 4096
LOGQ = 12
PREC = 12
set_random_seed(20261006)

# ---------------------------------------------------------------------------------------------
# Low-degree factors of X^L - 1 over Z/2^12 (from the 2-adic factorizations of Phi_d, d odd)
# ---------------------------------------------------------------------------------------------
ZX.<X> = ZZ[]
Zq = Zmod(q)
ZqX.<Y> = Zq[]

def factors_mod_q(d):
    """Factors of the d-th cyclotomic polynomial over Z/2^12 (d odd, so Phi_d is unramified at 2)."""
    K = Qp(2, prec=60)
    out = []
    for f, mult in cyclotomic_polynomial(d).change_ring(K).factor():
        assert mult == 1
        g = ZqX([Zq(ZZ(c.lift() if hasattr(c, "lift") else c)) for c in f.monic().list()])
        out.append(g)
    return out

TARGETS = [("X-1", ZqX(Y - 1))]
TARGETS += [("Phi3", g) for g in factors_mod_q(3)]
TARGETS += [(f"Phi7[{i}]", g) for i, g in enumerate(factors_mod_q(7))]
TARGETS += [(f"Phi21[{i}]", g) for i, g in enumerate(factors_mod_q(21))]

def check_divides(L):
    for name, g in TARGETS:
        r = (ZqX(Y**L - 1)) % g
        assert r == 0, f"{name} does not divide X^{L} - 1 mod q"

# ---------------------------------------------------------------------------------------------
# Lattice of functionals
# ---------------------------------------------------------------------------------------------
def reduction_matrix(g, n):
    """R_g in Z_q^{k x n}: column j = coefficients of X^(n-1-j) mod g (s~ = sum_j s_j X^(n-1-j))."""
    k = g.degree()
    R = matrix(Zq, k, n)
    p = ZqX(1)
    for deg in range(n):
        j = n - 1 - deg
        coeffs = p.list() + [0] * (k - len(p.list()))
        for t in range(k):
            R[t, j] = coeffs[t]
        p = (p * Y) % g
    return R

def constraint_matrix(HT, g):
    """B_g in Z_q^{(n-k) x m}: H^T phi = R_g^T c  <=>  B_g phi = 0, c_t = (H^T phi)_{n-1-t}."""
    n, m = HT.nrows(), HT.ncols()
    if g is None:
        return HT
    k = g.degree()
    R = reduction_matrix(g, n)
    for t in range(k):  # columns n-1-t of R_g are unit vectors
        assert all(R[tt, n - 1 - t] == (1 if tt == t else 0) for tt in range(k))
    rows = []
    for j in range(n - k):
        row = HT.row(j)
        for t in range(k):
            if R[t, j] != 0:
                row = row - R[t, j] * HT.row(n - 1 - t)
        rows.append(row)
    return matrix(Zq, rows)

def hankel_T(a, n, m):
    return matrix(Zq, n, m, lambda j, i: a[i + j])

def rank_mod2(B):
    return B.change_ring(GF(2)).rank()

def qary_basis(B):
    """Row basis of Lambda_q^perp(B) = { x in Z^m : B x = 0 mod q }, assuming B has full row rank mod 2."""
    r, m = B.nrows(), B.ncols()
    B2 = B.change_ring(GF(2))
    piv = B2.pivots()
    assert len(piv) == r, "B is not of full rank mod 2"
    free = [i for i in range(m) if i not in piv]
    B1 = B.matrix_from_columns(piv)
    Bf = B.matrix_from_columns(free)
    T = -(B1.inverse() * Bf)  # x_piv = T x_free  (mod q)
    rows = []
    for idx, col in enumerate(piv):  # q e_piv
        v = [0] * m
        v[col] = q
        rows.append(v)
    for jf, col in enumerate(free):  # e_free + T column
        v = [0] * m
        v[col] = 1
        for ip, pc in enumerate(piv):
            v[pc] = ZZ(T[ip, jf])
        rows.append(v)
    return rows

def log2_gh(m, logdet2):
    """log2 of the Gaussian heuristic for a rank-m lattice with log2(det) = logdet2."""
    return (lgamma(m / 2 + 1) / m - 0.5 * log(pi)) / log(2.0) + logdet2 / m

def guess_entropy(g, n):
    """Approximate entropy (bits) of s~ mod g for s ~ CBD_2^n: Gaussian with covariance R R^T
    (centered representatives of R_g, unit variance per coordinate), capped at 12 bits per coordinate."""
    if g is None:
        return 0.0
    k = g.degree()
    R = reduction_matrix(g, n)
    Rc = matrix(RDF, k, n, lambda t, j: ZZ(R[t, j]) - q if ZZ(R[t, j]) > q // 2 else ZZ(R[t, j]))
    S = Rc * Rc.transpose()
    h = 0.5 * (k * log2(2 * pi * E) + log2(abs(S.det())))
    return min(h, LOGQ * k)

def advantage_log2(length, sigma=1.0):
    """log2 of the distinguishing advantage exp(-2 pi^2 (length sigma / q)^2) of one functional."""
    return -2 * pi**2 * (length * sigma / q) ** 2 / log(2.0)

def shortest(rows):
    A = IntegerMatrix.from_matrix(rows)
    LLL.reduction(A)
    m = A.nrows
    if m > 40:
        BKZReduction(A)(BKZ.EasyParam(min(m, 40), max_loops=4))
    v = SVP.shortest_vector(A)
    return float(sqrt(sum(x * x for x in v)))

# ---------------------------------------------------------------------------------------------
# (2) Full size
# ---------------------------------------------------------------------------------------------
def full_size(trials=5):
    n, W = 640, 128
    m, L = n + W, 2 * n + W - 1
    check_divides(L)
    print(f"# Full size: n={n}, m={m}, L={L}, q={q}; {trials} random sequences a", flush=True)
    print("target   k  full-rank-mod-2 (Hankel)  log2 det  log2 GH  GH length  log2 adv. at GH  guess entropy (bits)  vs k coords of s", flush=True)
    for name, g in [("plain", None)] + TARGETS:
        k = 0 if g is None else g.degree()
        ok = 0
        for t in range(trials):
            a = [Zq.random_element() for _ in range(n + m - 1)]
            B = constraint_matrix(hankel_T(a, n, m), g)
            ok += int(rank_mod2(B) == n - k)
        ld = LOGQ * (n - k)
        lg = log2_gh(m, ld)
        print(f"{name:8s} {k:2d}  {ok}/{trials}                     {ld:7d}  {lg:7.2f}  {2**lg:9.0f}  {advantage_log2(2**lg):9.1f}        {guess_entropy(g, n):8.1f}            {2.031 * k:6.1f}", flush=True)

# ---------------------------------------------------------------------------------------------
# (3) Reduced sizes: exact shortest vectors, Hankel vs uniform
# ---------------------------------------------------------------------------------------------
def small(trials=20, sizes=((40, 5), (48, 10), (56, 15)), only=None, header=True):
    if header:
        print("# Reduced sizes: lambda_1 / GH over random instances (exact SVP after BKZ preprocessing)", flush=True)
        print("n   W   m   target    k  log2 GH   Hankel mean  min   max    | uniform mean  min   max   | rank-def (H/U)", flush=True)
    for n, W in sizes:
        m, L = n + W, 2 * n + W - 1
        check_divides(L)
        for name, g in [("plain", None)] + TARGETS:
            if only is not None and name != only:
                continue
            k = 0 if g is None else g.degree()
            if n - k >= m:
                continue
            lg = log2_gh(m, LOGQ * (n - k))
            gh = 2 ** lg
            res = {"H": [], "U": []}
            bad = {"H": 0, "U": 0}
            for kind in ("H", "U"):
                done = 0
                while done < trials:
                    if kind == "H":
                        a = [Zq.random_element() for _ in range(n + m - 1)]
                        B = constraint_matrix(hankel_T(a, n, m), g)
                    else:
                        B = random_matrix(Zq, n - k, m)
                    if rank_mod2(B) < n - k:
                        bad[kind] += 1
                        continue
                    res[kind].append(shortest(qary_basis(B)) / gh)
                    done += 1
            h, u = res["H"], res["U"]
            print(f"{n:3d} {W:3d} {m:3d}  {name:8s} {k:2d}  {lg:6.2f}   {sum(h)/len(h):.3f}  {min(h):.3f} {max(h):.3f}  |  {sum(u)/len(u):.3f}  {min(u):.3f} {max(u):.3f} | {bad['H']}/{bad['U']}", flush=True)

if True:  # sage scripts do not set __name__ to "__main__"
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    print("Targets (low-degree factors of X^L - 1 over Z/2^12):", [(nm, g.degree()) for nm, g in TARGETS], flush=True)
    t0 = time.time()
    if mode == "case":
        pass
    elif mode in ("full", "all"):
        full_size()
    if mode in ("small", "all"):
        small()
    if mode == "test":
        small(trials=2, sizes=((40, 5),))
    if mode == "case":  # sage functionals.sage case n W target trials seed
        n_, W_, target_, trials_, seed_ = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
        set_random_seed(seed_)
        small(trials=trials_, sizes=((n_, W_),), only=target_, header=False)
    print(f"# done in {time.time() - t0:.0f} s", flush=True)
