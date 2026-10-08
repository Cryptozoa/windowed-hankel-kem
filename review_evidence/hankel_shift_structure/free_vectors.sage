# Upper bound on what the shift structure can buy a dual attack (paper, Section 4.4).
#
# A short functional phi whose last t entries vanish has t shifts of the same length that are valid
# functionals for constraint sets shifted by one each (S phi satisfies the constraints J - 1). At best,
# shifts multiply the supply of short vectors without making them shorter. We grant the attacker that
# multiplication for free: every request for N short vectors is charged as a request for N / T, with no
# extra guessing, for T up to n = 640, and re-optimize the dual hybrid attack (MATZOV and Core-SVP).
# In both models a sieve call yields about 2^(0.2075 beta) vectors, and the cost of N vectors is
# ceil(N / 2^(0.2075 beta)) times the cost of one call (estimator/reduction.py).
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *

class FreeVectors:
    """Reduction cost model in which each sieve call supplies T times as many short vectors."""
    def __init__(self, base, T):
        self.base, self.T = base, T
    def __getattr__(self, k):
        return getattr(self.base, k)
    def __call__(self, *a, **kw):
        return self.base(*a, **kw)
    def __repr__(self):
        return f"{self.base!r}x{self.T}"
    def short_vectors(self, beta, d, N=None, B=None, preprocess=True, sieve_dim=None):
        if N is not None and N != 1:
            N = max(2, N / self.T)
        return self.base.short_vectors(beta, d, N=N, B=B, preprocess=preprocess, sieve_dim=sieve_dim)

WH = LWE.Parameters(n=640, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=768, tag="WH640")
for name, rc in (("MATZOV", RC.MATZOV), ("Core-SVP", RC.ADPS16)):
    base = None
    for T in (1, 2, 8, 64, 640):
        c = LWE.dual_hybrid(WH, red_cost_model=FreeVectors(rc, T))
        lr = float(log(c["rop"], 2))
        base = lr if base is None else base
        print(f"{name:8s} T = {T:4d}: rop 2^{lr:.2f} (change {lr - base:+.2f})  beta {c['beta']}  "
              f"zeta {c.get('zeta', '-')}  t {c.get('t', '-')}  log2 N {float(log(c['N'], 2)) if 'N' in c else float('nan'):.1f}",
              flush=True)
