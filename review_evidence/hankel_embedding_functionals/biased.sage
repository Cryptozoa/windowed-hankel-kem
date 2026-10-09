# Biased functionals from the cyclic embedding (paper, Section 4.3, Table 2 and Appendix C).
#
# Appendix C asks for functionals that isolate s~ mod g exactly: H^T phi = R_g^T c (mod q). A biased
# functional only approximates this, H^T phi = R_g^T c + w with w short, and gives
#     phi^T b = c^T (s~ mod g) + w^T s + phi^T e,
# which correlates with the k coefficients of s~ mod g as long as phi and w are short (s and e both have
# unit variance, so phi and w are weighted equally). With E_g in Z_q^{(n-k) x n} such that E_g x = 0 iff
# x = R_g^T c for some c (E_g = [I | -R'], from the unit columns of R_g), these functionals form the lattice
#     Lambda'_g = { (phi, w) in Z^{m+n} : E_g (H^T phi - w) = 0 mod q },
# of dimension m + n and determinant q^(n-k): E_g contains an identity block, so the constraints always
# have full rank. For g = 1 (k = 0) it is the lattice of the dual attack. The uniform twin replaces H^T by
# a uniform n x m matrix.
#
# Trivial vectors. For every c, (0, R_g^T c) lies in Lambda'_g: with phi = 0 the identity reads 0 = 0 and
# carries no information. For X - 1 and Phi_3 these vectors are short (X^i mod g has tiny coefficients),
# shorter than any useful functional, so a plain shortest-vector computation would only find them. We
# therefore project Lambda'_g orthogonally to the k vectors (0, R_g^T e_t) (centered representatives) and
# measure the projected lattice, of rank m + n - k and determinant det(Lambda'_g) / vol(trivial). A
# projected length is the length of (phi, w - R_g^T c) for the best real c, a slight lower bound on the
# useful length; Hankel and uniform matrices are treated identically.
#
#   (1) full size (n = 640, m = 768): Lambda'_g against the dual-hybrid lattice that guesses k coordinates
#       of s (dimension m + n - k, the same determinant), and the entropy of the guess;
#   (2) reduced sizes, Hankel against uniform matrices, as a ratio to the Gaussian heuristic: exact shortest
#       vectors at (n, W) = (24, 16) (dimension 64), and the first vector after BKZ-40 at (32, 21) and
#       (40, 5) (dimension 85), where exact enumeration is too slow for many instances. The dimension is
#       always m + n = L + 1, and 21 | L is needed for all six target factors to divide X^L - 1, so
#       L = 63 or 84.
#
# Run: sage biased.sage [full|small|all]   (conda-forge SageMath 10.9, fpylll 0.6.4; small: ~14 workers)
import sys, time, multiprocessing as mp
from math import lgamma, log2, pi, sqrt, e as E
from fpylll import IntegerMatrix, LLL, BKZ, SVP
from fpylll.algorithms.bkz2 import BKZReduction
from scipy.stats import mannwhitneyu

q, LOGQ = 4096, 12
Zq = Zmod(q)
ZqX.<Y> = Zq[]
TRIALS = 20


def factors_mod_q(d):
    K = Qp(2, prec=60)
    return [ZqX([Zq(ZZ(c.lift() if hasattr(c, "lift") else c)) for c in f.monic().list()])
            for f, mult in cyclotomic_polynomial(d).change_ring(K).factor()]


TARGETS = [("plain", None), ("X-1", ZqX(Y - 1))]
TARGETS += [("Phi3", g) for g in factors_mod_q(3)]
TARGETS += [(f"Phi7[{i}]", g) for i, g in enumerate(factors_mod_q(7))]
TARGETS += [(f"Phi21[{i}]", g) for i, g in enumerate(factors_mod_q(21))]


def reduction_matrix(g, n):
    """R_g: column j = coefficients of X^(n-1-j) mod g, so that R_g s = coefficients of s~ mod g."""
    k = g.degree()
    R = matrix(Zq, k, n)
    p = ZqX(1)
    for deg in range(n):
        coeffs = p.list() + [0] * (k - len(p.list()))
        for t in range(k):
            R[t, n - 1 - deg] = coeffs[t]
        p = (p * Y) % g
    return R


def E_matrix(g, n):
    """E_g in Z_q^{(n-k) x n} with E_g x = 0 iff x = R_g^T c: row j = e_j - sum_t R[t, j] e_{n-1-t}."""
    if g is None:
        return identity_matrix(Zq, n)
    k = g.degree()
    R = reduction_matrix(g, n)
    for t in range(k):
        assert all(R[tt, n - 1 - t] == (1 if tt == t else 0) for tt in range(k))
    Em = matrix(Zq, n - k, n)
    for j in range(n - k):
        Em[j, j] = 1
        for t in range(k):
            Em[j, n - 1 - t] -= R[t, j]
    return Em


def qary_basis(B):
    """Row basis of { x in Z^N : B x = 0 mod q }, B of full row rank mod 2."""
    r, N = B.nrows(), B.ncols()
    piv = B.change_ring(GF(2)).pivots()
    assert len(piv) == r
    free = [i for i in range(N) if i not in piv]
    T = -(B.matrix_from_columns(piv).inverse() * B.matrix_from_columns(free))
    rows = []
    for col in piv:
        v = [0] * N
        v[col] = q
        rows.append(v)
    for jf, col in enumerate(free):
        v = [0] * N
        v[col] = 1
        for ip, pc in enumerate(piv):
            v[pc] = ZZ(T[ip, jf])
        rows.append(v)
    return rows


def log2_gh(d, logdet2):
    return (lgamma(d / 2 + 1) / d - 0.5 * log(pi)) / log(2.0) + logdet2 / d


def guess_entropy(g, n):
    """Entropy of s~ mod g for s ~ CBD_2^n (Gaussian approximation), capped at 12 bits per coefficient."""
    if g is None:
        return 0.0
    k = g.degree()
    R = reduction_matrix(g, n)
    Rc = matrix(RDF, k, n, lambda t, j: ZZ(R[t, j]) - q if ZZ(R[t, j]) > q // 2 else ZZ(R[t, j]))
    h = 0.5 * (k * log2(2 * pi * E) + log2(abs((Rc * Rc.transpose()).det())))
    return min(h, LOGQ * k)


def biased_lattice(HT, g):
    """Basis of Lambda'_g = { (phi, w) : E_g (H^T phi - w) = 0 mod q }."""
    n = HT.nrows()
    Em = E_matrix(g, n)
    M = (Em * HT).augment(-Em)
    return qary_basis(M)


def trivial_vectors(g, n, m):
    """The k vectors (0, R_g^T e_t) of Lambda'_g, with centered entries."""
    if g is None:
        return []
    R = reduction_matrix(g, n)
    cen = lambda x: ZZ(x) - q if ZZ(x) > q // 2 else ZZ(x)
    return [vector(ZZ, [0] * m + [cen(R[t, j]) for j in range(n)]) for t in range(g.degree())]


def projected_shortest(rows, triv, exact=True):
    """Shortest vector (exact, or the first vector after BKZ-40) of the projection of the lattice
    orthogonally to the trivial vectors; returns (length, log2 of the projected determinant, rank)."""
    B = matrix(QQ, rows)
    d = B.nrows()
    logdet = log(abs(matrix(ZZ, rows).det()), 2)
    if triv:
        S = matrix(QQ, triv)
        G = S * S.transpose()
        P = identity_matrix(QQ, d) - S.transpose() * G.inverse() * S
        Bp = B * P
        D = lcm([x.denominator() for x in Bp.list()])
        A = IntegerMatrix.from_matrix((D * Bp).change_ring(ZZ).rows())
        LLL.reduction(A)  # removes the k linear dependencies as zero rows
        rows_nz = [list(A[i]) for i in range(A.nrows) if any(A[i])]
        A = IntegerMatrix.from_matrix(rows_nz)
        logdet -= float(0.5 * log(G.det(), 2))
        scale = D
    else:
        A = IntegerMatrix.from_matrix(rows)
        LLL.reduction(A)
        scale = 1
    r = A.nrows
    if r > 40:
        BKZReduction(A)(BKZ.EasyParam(40, max_loops=4 if exact else 8))
    v = SVP.shortest_vector(A) if exact else list(A[0])
    return float(sqrt(sum(x * x for x in v))) / float(scale), float(logdet), r


def full_size():
    n, W = 640, 128
    m = n + W
    print(f"# Full size: n = {n}, m = {m}, q = {q}", flush=True)
    print("target    k  biased lattice: dim  log2 det  log2 GH | dual hybrid (k coords): dim  log2 GH | "
          "guess bits: s~ mod g  vs k coords", flush=True)
    for name, g in TARGETS:
        k = 0 if g is None else g.degree()
        d1, d2, ld = m + n, m + n - k, LOGQ * (n - k)
        print(f"{name:8s} {k:2d}   {d1:5d}  {ld:7d}  {log2_gh(d1, ld):7.3f} |   {d2:5d}  {log2_gh(d2, ld):7.3f} |"
              f"   {guess_entropy(g, n):7.1f}   {2.031 * k:6.1f}", flush=True)


def job(args):
    n, W, ti, kind, seed, exact = args
    set_random_seed(seed)
    m = n + W
    name, g = TARGETS[ti]
    if kind == "hankel":
        a = [Zq.random_element() for _ in range(n + m - 1)]
        HT = matrix(Zq, n, m, lambda j, i: a[i + j])
    else:
        HT = random_matrix(Zq, n, m)
    length, logdet, rank = projected_shortest(biased_lattice(HT, g), trivial_vectors(g, n, m), exact)
    return n, W, ti, kind, length / 2 ** log2_gh(rank, logdet)


def small(sizes=((24, 16, True), (32, 21, False), (40, 5, False))):
    for n, W, _ in sizes:
        L = 2 * n + W - 1
        for name, g in TARGETS:
            if g is not None:
                assert (ZqX(Y ** L - 1) % g) == 0
    jobs = [(n, W, ti, kind, 10 ** 7 * n + 10 ** 5 * ti + 2 * t + (kind == "uniform"), exact)
            for n, W, exact in sizes for ti in range(len(TARGETS)) for t in range(TRIALS) for kind in ("hankel", "uniform")]
    res = {}
    with mp.get_context("fork").Pool(14) as pool:
        for n, W, ti, kind, r in pool.imap_unordered(job, jobs, chunksize=2):
            res.setdefault((n, W, ti, kind), []).append(r)
    print(f"# Reduced sizes: lambda_1 / GH of the biased lattice with the trivial vectors projected away, "
          f"{TRIALS} instances per kind and target", flush=True)
    print("  n   W   m    d  measure   target    k |  Hankel mean   min |  uniform mean   min |  Mann-Whitney p", flush=True)
    for n, W, exact in sizes:
        m = n + W
        for ti, (name, g) in enumerate(TARGETS):
            k = 0 if g is None else g.degree()
            h, u = res[(n, W, ti, "hankel")], res[(n, W, ti, "uniform")]
            p = mannwhitneyu(h, u, alternative="two-sided").pvalue
            print(f"{n:3d} {W:3d} {m:3d} {m + n:4d}  {'exact  ' if exact else 'BKZ-40 '}  {name:8s} {k:2d} |  {sum(h) / len(h):.3f}  {min(h):.3f} |"
                  f"  {sum(u) / len(u):.3f}  {min(u):.3f} |  {p:.3f}", flush=True)


mode = sys.argv[1] if len(sys.argv) > 1 else "all"
print("Sage", sage.version.version, "| targets:", [(nm, 0 if g is None else g.degree()) for nm, g in TARGETS], flush=True)
t0 = time.time()
if mode in ("full", "all"):
    full_size()
if mode in ("small", "all"):
    small()
if mode == "test":
    TRIALS = 2
    small(sizes=((24, 16, True), (32, 21, False)))
print(f"# done in {time.time() - t0:.0f} s", flush=True)
