# Run from this directory:  LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_full.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
import sage_flint_shim; sage_flint_shim.install()
P = LWE.Parameters(n=640, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=768, tag="WindowedHankel640")
print(P)
print("--- rough (ADPS16 Core-SVP) ---", flush=True)
LWE.estimate.rough(P)
print("--- full (MATZOV) ---", flush=True)
LWE.estimate(P, deny_list=("arora-gb",))
