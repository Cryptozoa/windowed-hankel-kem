# Algebraic decoding with small errors: XL on Arora-Ge systems, Hankel versus uniform (paper, Section 4.3).
#
# A noise-tolerant Pade decoder would have to use that the errors are small. The algebraic way to do so
# is Arora-Ge: for noise in {-1, 0, 1}, each sample gives the cubic equation
#     f_i(x) = (b_i - <A_i, x>) (b_i - <A_i, x> - 1) (b_i - <A_i, x> + 1) = 0,
# and a secret in {-1, 0, 1}^n adds x_j^3 - x_j = 0. XL at degree D multiplies every equation by every
# monomial of degree <= D - 3 and row-reduces the resulting Macaulay matrix; it succeeds when the row space
# contains x_j - s_j for every j. If the Hankel structure helped algebraic decoding, Hankel systems would
# succeed with fewer samples or at a lower degree than systems with uniform A.
#
# Field: GF(4093), the largest prime below 2^12 (XL needs a field). Secret and noise: CBD_1, that is
# 0 with probability 1/2 and +-1 with probability 1/4 each. For each (n, D) we find, per kind of matrix,
# the success rate as a function of m.
#
# Run: sage xl.sage  (about 10 minutes on 14 cores)
import itertools, multiprocessing as mp, sys
from scipy.stats import mannwhitneyu

p = 4093
F = GF(p)
TRIALS = 24

def cbd1():
    return F(randint(0, 1) - randint(0, 1))

def instance(kind, n, m, seed):
    set_random_seed(seed)
    if kind == "hankel":
        a = [F.random_element() for _ in range(n + m - 1)]
        A = matrix(F, m, n, lambda i, j: a[i + j])
    else:
        A = random_matrix(F, m, n)
    s = vector(F, [cbd1() for _ in range(n)])
    e = vector(F, [cbd1() for _ in range(m)])
    return A, A * s + e, s

def xl_solves(kind, n, m, D, seed):
    A, b, s = instance(kind, n, m, seed)
    R = PolynomialRing(F, "x", n, order="degrevlex")
    x = R.gens()
    eqs = []
    for i in range(m):
        l = b[i] - sum(A[i, j] * x[j] for j in range(n))
        eqs.append(l * (l - 1) * (l + 1))
    eqs += [xj ** 3 - xj for xj in x]
    mults = [R(1)] + [prod(c) for d in range(1, D - 2) for c in itertools.combinations_with_replacement(x, d)]
    rows = [f * u for f in eqs for u in mults]
    # columns: monomials of degree >= 2 first, then x_1..x_n, then 1
    mons = sorted({t for f in rows for t in f.monomials()}, key=lambda t: (-t.degree(), t), reverse=False)
    high = [t for t in mons if t.degree() >= 2]
    cols = high + list(x) + [R(1)]
    idx = {t: k for k, t in enumerate(cols)}
    M = matrix(F, len(rows), len(cols), sparse=False)
    for r, f in enumerate(rows):
        for c, t in zip(f.coefficients(), f.monomials()):
            M[r, idx[t]] = c
    E = M.echelon_form()
    nh = len(high)
    found = {}
    for r in range(E.nrows()):
        row = E.row(r)
        nz = row.nonzero_positions()
        if not nz:
            break
        lead = nz[0]
        if nh <= lead < nh + n and all(k == lead or k == len(cols) - 1 for k in nz):
            found[lead - nh] = -row[len(cols) - 1]
    ok = len(found) == n and all(found[j] == s[j] for j in range(n))
    rank = E.rank()
    return kind, n, m, D, seed, bool(ok), M.nrows(), M.ncols(), M.ncols() - rank

def job(args):
    return xl_solves(*args)

print("Sage", sage.version.version, flush=True)
print(f"GF({p}), secret and noise CBD_1, {TRIALS} trials per kind and point", flush=True)
# every m around each threshold (a first scan with coarser steps placed the thresholds)
CONFIG = [(5, 4, range(12, 20)), (5, 5, range(3, 10)), (6, 4, range(18, 27)), (6, 5, range(8, 15)),
          (7, 5, range(11, 18)), (8, 5, range(18, 27)), (8, 6, range(8, 15))]
jobs = [(kind, n, m, D, 10**6 * n + 10**4 * D + 100 * m + 2 * t + (kind == "uniform"))
        for n, D, ms in CONFIG for m in ms for t in range(TRIALS) for kind in ("hankel", "uniform")]
res = {}
with mp.get_context("fork").Pool(14) as pool:  # the default "spawn" cannot re-import a Sage script
    for kind, n, m, D, seed, ok, nr, nc, ker in pool.imap_unordered(job, jobs, chunksize=4):
        res.setdefault((n, D, m, kind), []).append(ok)
        res.setdefault((n, D, m, kind + "_ker"), []).append(ker)
        res[(n, D, m, "size")] = (nr, nc)
for n, D, ms in CONFIG:
    print(f"\nn = {n}, D = {D}: success rate by m (Hankel / uniform), Macaulay matrix rows x columns, "
          f"kernel dimension mean (Hankel / uniform)", flush=True)
    th = {"hankel": None, "uniform": None}
    for m in ms:
        h, u = res[(n, D, m, "hankel")], res[(n, D, m, "uniform")]
        nr, nc = res[(n, D, m, "size")]
        kh, ku = res[(n, D, m, "hankel_ker")], res[(n, D, m, "uniform_ker")]
        print(f"  m = {m:3d}: {sum(h):2d}/{len(h)}  {sum(u):2d}/{len(u)}   ({nr} x {nc})   "
              f"kernel {sum(kh) / len(kh):7.2f} / {sum(ku) / len(ku):7.2f}"
              f"{'' if kh == ku else '  (differ: ' + str(sorted(set(kh))) + ' / ' + str(sorted(set(ku))) + ')'}", flush=True)
        for kind, v in (("hankel", h), ("uniform", u)):
            if th[kind] is None and sum(v) * 2 >= len(v):
                th[kind] = m
    print(f"  smallest m with success rate >= 1/2: Hankel {th['hankel']}, uniform {th['uniform']}", flush=True)
