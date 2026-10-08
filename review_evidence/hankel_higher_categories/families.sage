# Cheapest of primal (uSVP) and dual hybrid, in both cost models, for a parameter family over a range of n.
# Run: sage families.sage FAMILY q eta bits n_lo n_hi step
# Families: A q=2^13 CBD2 2 bits; B q=2^12 CBD2 1 bit; C q=2^12 CBD1 2 bits; D q=2^13 CBD3 1 bit.
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
from dfr import log2_dfr
fam, q, eta, bits = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
lo, hi, step = int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7])
W = 256 // bits
qb = q.bit_length() - 1
for n in range(lo, hi + 1, step):
    m = n + W
    P = LWE.Parameters(n=n, q=q, Xs=ND.CenteredBinomial(eta), Xe=ND.CenteredBinomial(eta), m=m)
    r = []
    for rc in (RC.ADPS16, RC.MATZOV):
        u = LWE.primal_usvp(P, red_cost_model=rc); d = LWE.dual_hybrid(P, red_cost_model=rc)
        r.append(min(float(log(u['rop'], 2)), float(log(d['rop'], 2))))
    pk = 12 + 32 + (m * qb + 7) // 8
    ct = 12 + ((m + W) * qb + 7) // 8
    print(f"{fam} n={n} q=2^{qb} eta={eta} bits={bits} | min CoreSVP {r[0]:.1f} MATZOV {r[1]:.1f} | "
          f"DFR 2^{log2_dfr(n, q, eta, bits):.1f} | pk {pk} ct {ct} total {pk+ct}", flush=True)
