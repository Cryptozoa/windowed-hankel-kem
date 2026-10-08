# Attack breakdown for the proposed Category 3 and 5 sets (q = 2^13, CBD_2, 4-PAM, W = 128).
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
for label, n in (("Cat3 n=936", 936), ("Cat5 n=1208", 1208)):
    P = LWE.Parameters(n=n, q=8192, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=n + 128, tag=label)
    for an, fn in (("usvp", LWE.primal_usvp), ("bdd", LWE.primal_bdd), ("dual", LWE.dual), ("dual_hybrid", LWE.dual_hybrid)):
        row = []
        for rc in (RC.ADPS16, RC.MATZOV):
            c = fn(P, red_cost_model=rc)
            row.append(f"beta {c.get('beta')} rop 2^{float(log(c['rop'], 2)):.1f}")
        print(f"{label} {an:12s} CoreSVP {row[0]:22s} | MATZOV {row[1]}", flush=True)
    c = LWE.coded_bkw(P)
    print(f"{label} coded_bkw    rop 2^{float(log(c['rop'], 2)):.1f}", flush=True)
