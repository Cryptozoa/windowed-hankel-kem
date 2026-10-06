# Run from this directory:  LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_kyber512_bkw.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
import sage_flint_shim; sage_flint_shim.install()
print("Kyber512 coded-bkw ::", LWE.coded_bkw(schemes.Kyber512))
