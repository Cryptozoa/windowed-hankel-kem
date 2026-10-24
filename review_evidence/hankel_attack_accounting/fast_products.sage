# Where fast Hankel products could enter the attacks of the paper's estimates (Section 7).
# Hankel matrix-vector products cost O((m + n) log(m + n)) by FFT instead of m n. In the dual hybrid attack
# of the lattice estimator (lattice-estimator 53da598, class MATZOV, used for the paper's figures), the
# per-candidate work, the FFT over t coordinates and the table updates over the N short dual vectors, does
# not multiply by A. Products with A occur once: each of the N dual vectors (of length m) is multiplied by
# the zeta + t guessed columns of A, about N m (zeta + t) operations, which the model does not charge. This
# script prints that one-time cost at the published optima, next to the total. Primal attacks are lattice
# reduction alone. Run with native Sage 10.9:  ESTIMATOR=/path/to/lattice-estimator sage fast_products.sage
import os, sys
sys.path.insert(0, os.environ.get("ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
p = LWE.Parameters(n=640, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=768, tag="WH-640")
for name, rc in (("Core-SVP (ADPS16)", RC.ADPS16), ("MATZOV", RC.MATZOV)):
    c = LWE.dual_hybrid(p, red_cost_model=rc)
    k = c["zeta"] + c["t"]
    once = c["N"] * c["m"] * k
    print(f"{name}: {c!r}", flush=True)
    print(f"  one-time products of the N dual vectors with the {k} guessed columns: N m (zeta + t) = 2^{float(log(once, 2)):.1f}, "
          f"against 2^{float(log(c['rop'], 2)):.1f} in total", flush=True)
