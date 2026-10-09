# Run from this directory:  LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_param_grid.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
# Paper Table 5: primal and dual hybrid costs and sizes for parameter alternatives.
import os, sys
sys.path.insert(0, os.path.expanduser("~/Documents/lattice-estimator"))
sys.path.insert(0, os.getcwd())
from estimator import *
import sage_flint_shim; sage_flint_shim.install()
cases = [  # (n, q, eta, W)
    (512, 4096, 2, 128), (576, 4096, 2, 128), (640, 4096, 2, 128), (704, 4096, 2, 128),
    (640, 2048, 1, 128), (640, 8192, 3, 128), (704, 2048, 1, 128),
]
for n, q, eta, W in cases:
    m = n + W
    P = LWE.Parameters(n=n, q=q, Xs=ND.CenteredBinomial(eta), Xe=ND.CenteredBinomial(eta), m=m)
    u = LWE.primal_usvp(P, red_cost_model=RC.ADPS16)
    d = LWE.dual_hybrid(P, red_cost_model=RC.ADPS16)
    um = LWE.primal_usvp(P, red_cost_model=RC.MATZOV)
    dm = LWE.dual_hybrid(P, red_cost_model=RC.MATZOV)
    bits = q.bit_length() - 1
    pk = 12 + 32 + m * bits // 8
    ct = 12 + (m + W) * bits // 8
    print(f"n={n} q=2^{bits} eta={eta} | coreSVP usvp {float(log(u['rop'],2)):.1f} dualhyb {float(log(d['rop'],2)):.1f} "
          f"(beta {d['beta']}) | MATZOV usvp {float(log(um['rop'],2)):.1f} dualhyb {float(log(dm['rop'],2)):.1f} | pk {pk} ct {ct} total {pk+ct}", flush=True)
