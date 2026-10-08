# Predicted primal-uSVP block size (lattice estimator, 2016 estimate) for reduced Windowed Hankel instances:
# q = 4096, CBD_2 secret and error, m <= 1.2 n samples. Used to choose the sizes of the experiment.
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
for n in range(60, 241, 20):
    P = LWE.Parameters(n=n, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=floor(1.2 * n))
    c = LWE.primal_usvp(P, red_cost_model=RC.ADPS16)
    print(f"n {n:4d}  m_max {floor(1.2*n):4d}  beta {c['beta']:4d}  d {c['d']:4d}  (samples used {c['d'] - n - 1})", flush=True)
