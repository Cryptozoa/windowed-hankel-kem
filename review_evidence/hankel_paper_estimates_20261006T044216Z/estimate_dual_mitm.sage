# Run from this directory:  LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_dual_mitm.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
# Dual hybrid with meet-in-the-middle guessing (tag dual_mitm_hybrid), which LWE.estimate does not run.
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
from estimator.lwe_dual import dual_hybrid as dual_hybrid_fn
import sage_flint_shim; sage_flint_shim.install()
for n, q, eta, m in [(640, 4096, 2, 768), (640, 2048, 1, 768), (704, 2048, 1, 832)]:
    P = LWE.Parameters(n=n, q=q, Xs=ND.CenteredBinomial(eta), Xe=ND.CenteredBinomial(eta), m=m)
    for rc_name, rc in (("CoreSVP", RC.ADPS16), ("MATZOV", RC.MATZOV)):
        try:
            c = dual_hybrid_fn(P, red_cost_model=rc, mitm_optimization=True)
            print(f"n={n} q={q} eta={eta} {rc_name:7s} dual_mitm_hybrid  rop 2^{float(log(c['rop'],2)):.1f}  beta {c.get('beta')}", flush=True)
        except Exception as ex:
            print(f"n={n} q={q} eta={eta} {rc_name:7s} dual_mitm_hybrid  failed: {ex}", flush=True)
