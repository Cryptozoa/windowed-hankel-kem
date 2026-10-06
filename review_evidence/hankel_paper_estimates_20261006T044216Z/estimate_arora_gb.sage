# Run from this directory:  LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_arora_gb.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
# Arora-Ge / Groebner-basis estimate. Uses sage_flint_shim.install_gb(): the estimator's gb_cost
# fails in this Sage build (FLINT exception); validate_gb_shim.sage checks the replacement.
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
from math import log2
import sage_flint_shim; sage_flint_shim.install(); sage_flint_shim.install_gb()
for n, q, eta, m in [(640, 4096, 2, 768), (640, 2048, 1, 768)]:
    P = LWE.Parameters(n=n, q=q, Xs=ND.CenteredBinomial(eta), Xe=ND.CenteredBinomial(eta), m=m)
    c = LWE.arora_gb(P)
    r = "inf" if c["rop"] == oo else f"2^{log2(int(c['rop'])):.1f}"  # exact: rop exceeds float range
    print(f"n={n} q={q} eta={eta} arora-gb :: rop {r} dreg {c['dreg']} m {c.get('m')} t {c.get('t')}", flush=True)
