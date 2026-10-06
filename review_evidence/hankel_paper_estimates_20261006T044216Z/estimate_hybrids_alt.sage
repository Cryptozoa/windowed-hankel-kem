# Run from this directory:  LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_hybrids_alt.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
# Attacks the default LWE.estimate run either suppresses (hybrids that are not the cheapest) or that
# for the current parameters and two q = 2^11, CBD_1 alternatives. Arora-GB: estimate_arora_gb.sage;
# dual MITM hybrid: estimate_dual_mitm.sage.
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
import sage_flint_shim; sage_flint_shim.install()
from functools import partial
cases = [(640, 4096, 2, 768), (640, 2048, 1, 768), (704, 2048, 1, 832)]
for n, q, eta, m in cases:
    P = LWE.Parameters(n=n, q=q, Xs=ND.CenteredBinomial(eta), Xe=ND.CenteredBinomial(eta), m=m)
    for rc_name, rc in (("CoreSVP", RC.ADPS16), ("MATZOV", RC.MATZOV)):
        attacks = [
            ("bdd_hybrid", partial(LWE.primal_hybrid, mitm=False, babai=False, red_cost_model=rc)),
            ("bdd_mitm_hybrid", partial(LWE.primal_hybrid, mitm=True, babai=True, red_cost_model=rc)),
        ]
        for name, f in attacks:
            try:
                c = f(P)
                print(f"n={n} q={q} eta={eta} {rc_name:7s} {name:17s} rop 2^{float(log(c['rop'],2)):.1f}  beta {c.get('beta')}", flush=True)
            except Exception as ex:
                print(f"n={n} q={q} eta={eta} {rc_name:7s} {name:17s} failed: {ex}", flush=True)
