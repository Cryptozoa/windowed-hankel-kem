# Run from this directory:  LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_coresvp_detail.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
import sage_flint_shim; sage_flint_shim.install()
P = LWE.Parameters(n=640, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=768, tag="WH640")
for T in (P, schemes.Kyber512):
    for name, fn in [("usvp", LWE.primal_usvp), ("bdd", LWE.primal_bdd), ("dual", LWE.dual), ("dual_hybrid", LWE.dual_hybrid)]:
        c = fn(T, red_cost_model=RC.ADPS16)
        print(T.tag, name, "beta=", c.get("beta"), "rop=2^%.1f" % float(log(c["rop"],2)), "red=2^%.1f" % float(log(c["red"],2)) if "red" in c else "", "0.265b=%.1f" % (0.265*c["beta"]), flush=True)
